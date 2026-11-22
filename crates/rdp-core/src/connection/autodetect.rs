//! Answering network characteristics detection (MS-RDPBCGR 2.2.14).
//!
//! The Client Core Data advertises `RNS_UD_CS_SUPPORT_NETCHAR_AUTODETECT`,
//! and that bit is a promise: a server that sees it may run connect time
//! detection between the Client Info PDU and the Demand Active and wait for
//! the answers before it carries on. Windows gives up and uses its own
//! default. gnome-remote-desktop does not: it sends a Bandwidth Measure Start
//! and Stop, then waits for the Bandwidth Measure Results with no timeout at
//! all, then sends ten RTT Measure Requests and waits for the last response.
//! A client that stays silent leaves both ends reading, which is the
//! "stuck on Negotiating" of issue #59.
//!
//! So this answers the two requests that expect a reply. An RTT Measure
//! Request gets an RTT Measure Response with the same sequence number
//! (2.2.14.2.1). A Bandwidth Measure Stop gets a Bandwidth Measure Results
//! carrying the milliseconds since the matching Start and the payload bytes
//! that arrived in between (2.2.14.2.2). Everything else (the Start, the
//! Payload filler, the server's Network Characteristics Result) is
//! information and has no answer.
//!
//! The same responder serves the connection sequence and the connected pump,
//! because a server keeps sending RTT requests during the session to pace its
//! frames, and the advertised bit covers those too.

use std::time::Instant;

use rdp_pdu::rdp::{AutoDetectBody, AutoDetectKind, AutoDetectPdu, AutoDetectResponse};

/// A bandwidth measurement in progress: when the Start arrived and how many
/// payload bytes have arrived since.
#[derive(Debug, Clone, Copy)]
struct Measure {
    started: Instant,
    bytes: u64,
}

/// The client half of network characteristics detection.
#[derive(Debug, Default)]
pub struct AutoDetectResponder {
    measure: Option<Measure>,
}

impl AutoDetectResponder {
    /// A responder with no measurement in progress.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Take one request in and return the response it needs, if any.
    ///
    /// `now` is when the request arrived. It is a parameter so the arithmetic
    /// can be tested without sleeping.
    pub fn answer(
        &mut self,
        pdu: &AutoDetectPdu<'_>,
        now: Instant,
    ) -> Option<AutoDetectResponse<'static>> {
        use rdp_pdu::rdp::control::autodetect;

        if pdu.header_type_id != autodetect::TYPE_ID_REQUEST {
            return None;
        }
        let payload_len = match &pdu.body {
            AutoDetectBody::Payload(filler) => filler.len() as u64,
            _ => 0,
        };
        match pdu.classify().0 {
            AutoDetectKind::RttMeasure => Some(AutoDetectResponse::rtt(pdu.sequence_number)),
            AutoDetectKind::BandwidthStart => {
                self.measure = Some(Measure {
                    started: now,
                    bytes: 0,
                });
                None
            }
            AutoDetectKind::BandwidthPayload => {
                if let Some(m) = self.measure.as_mut() {
                    m.bytes = m.bytes.saturating_add(payload_len);
                }
                None
            }
            AutoDetectKind::BandwidthStop => {
                // A Stop without a Start is a server bug, and it still gets an
                // answer: a server waiting for the results waits whatever the
                // reason, and a zero delta is honest about what we saw.
                let m = self.measure.take().unwrap_or(Measure {
                    started: now,
                    bytes: 0,
                });
                let bytes = m.bytes.saturating_add(payload_len);
                let time_delta = now.saturating_duration_since(m.started).as_millis();
                let time_delta = u32::try_from(time_delta).unwrap_or(u32::MAX);
                let byte_count = u32::try_from(bytes).unwrap_or(u32::MAX);
                let continuous = pdu.request_type == autodetect::BANDWIDTH_STOP_CONTINUOUS;
                Some(if continuous {
                    AutoDetectResponse::bandwidth_results_continuous(
                        pdu.sequence_number,
                        time_delta,
                        byte_count,
                    )
                } else {
                    AutoDetectResponse::bandwidth_results(
                        pdu.sequence_number,
                        time_delta,
                        byte_count,
                    )
                })
            }
            AutoDetectKind::NetworkCharacteristicsResult => {
                if let AutoDetectBody::NetworkCharacteristics {
                    base_rtt,
                    bandwidth,
                    average_rtt,
                } = pdu.body
                {
                    tracing::debug!(
                        ?base_rtt,
                        ?bandwidth,
                        ?average_rtt,
                        "the server reported the network characteristics"
                    );
                }
                None
            }
            AutoDetectKind::BandwidthResults
            | AutoDetectKind::NetworkCharacteristicsSync
            | AutoDetectKind::Unknown => {
                tracing::debug!(
                    request_type = pdu.request_type,
                    "a detection request with no answer in this build"
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rdp_pdu::io::Payload;
    use rdp_pdu::rdp::control::autodetect;
    use std::time::Duration;

    fn request(request_type: u16, sequence_number: u16, body: AutoDetectBody<'_>) -> AutoDetectPdu<'_> {
        AutoDetectPdu {
            header_type_id: autodetect::TYPE_ID_REQUEST,
            sequence_number,
            request_type,
            body,
        }
    }

    #[test]
    fn an_rtt_request_is_answered_with_its_own_sequence_number() {
        let mut r = AutoDetectResponder::new();
        for code in [autodetect::RTT_REQUEST_CONNECT, autodetect::RTT_REQUEST_CONTINUOUS] {
            let out = r
                .answer(&request(code, 7, AutoDetectBody::Empty), Instant::now())
                .expect("an rtt request needs a response");
            assert_eq!(out.pdu.header_type_id, autodetect::TYPE_ID_RESPONSE);
            assert_eq!(out.pdu.request_type, autodetect::RTT_RESPONSE);
            assert_eq!(out.pdu.sequence_number, 7);
        }
    }

    /// The shape gnome-remote-desktop sends: a Start, some Payloads, and a
    /// Stop carrying the last filler, all with sequence number zero.
    #[test]
    fn a_bandwidth_measurement_is_answered_with_bytes_and_milliseconds() {
        let mut r = AutoDetectResponder::new();
        let filler = vec![0u8; 1000];
        let t0 = Instant::now();
        assert!(r
            .answer(&request(autodetect::BANDWIDTH_START_CONNECT, 0, AutoDetectBody::Empty), t0)
            .is_none());
        for _ in 0..3 {
            assert!(r
                .answer(
                    &request(
                        autodetect::BANDWIDTH_PAYLOAD,
                        0,
                        AutoDetectBody::Payload(Payload::new(&filler))
                    ),
                    t0 + Duration::from_millis(5)
                )
                .is_none());
        }
        let out = r
            .answer(
                &request(
                    autodetect::BANDWIDTH_STOP_CONNECT,
                    0,
                    AutoDetectBody::Payload(Payload::new(&filler)),
                ),
                t0 + Duration::from_millis(12),
            )
            .expect("a bandwidth stop needs the results");
        assert_eq!(out.pdu.request_type, autodetect::BANDWIDTH_RESULTS);
        assert_eq!(
            out.pdu.body,
            AutoDetectBody::Results {
                time_delta: 12,
                byte_count: 4000
            }
        );
    }

    #[test]
    fn a_continuous_measurement_is_answered_with_the_continuous_code() {
        let mut r = AutoDetectResponder::new();
        let t0 = Instant::now();
        r.answer(&request(autodetect::BANDWIDTH_START_CONTINUOUS, 3, AutoDetectBody::Empty), t0);
        let out = r
            .answer(
                &request(autodetect::BANDWIDTH_STOP_CONTINUOUS, 3, AutoDetectBody::Empty),
                t0 + Duration::from_millis(40),
            )
            .unwrap();
        assert_eq!(out.pdu.request_type, autodetect::BANDWIDTH_RESULTS_CONTINUOUS);
        assert_eq!(out.pdu.sequence_number, 3);
    }

    #[test]
    fn information_only_pdus_get_no_answer() {
        let mut r = AutoDetectResponder::new();
        let result = request(
            autodetect::NETCHAR_RESULT_ALL,
            1,
            AutoDetectBody::NetworkCharacteristics {
                base_rtt: Some(1),
                bandwidth: Some(2),
                average_rtt: Some(3),
            },
        );
        assert!(r.answer(&result, Instant::now()).is_none());
        // A response that somehow comes back to us is not answered either.
        let echo = AutoDetectPdu::rtt_response(9);
        assert!(r.answer(&echo, Instant::now()).is_none());
    }
}
