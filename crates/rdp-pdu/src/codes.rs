//! The code tables as Rust enums: ERRINFO, negotiation failure, licensing and
//! logon (PRDRDP/13 §8).
//!
//! One pattern, applied to every table, and the pattern is the one `vnc-core`
//! does not have and needs: a value we do not know is preserved rather than
//! lost. Every enum below has an `Unknown` variant carrying the wire value, so
//! a code from a Windows build newer than this one still round trips, still
//! logs as a number, and still reaches the user.
//!
//! What is here is the code, its specification symbol and one line of English.
//! What is not here is what the session does about it. The classification of
//! an ERRINFO into transient, fatal, user or expected is PRDRDP/06 §4.3's
//! table and is applied in `rdp-core`, because classification is policy
//! (PRDRDP/13 §4.10.2).
//!
//! The MCS result and disconnect reason codes live in
//! [`mcs`](crate::mcs) beside the PDUs that carry them, and the negotiation
//! failure values live in [`x224::neg_failure`](crate::x224::neg_failure);
//! [`NegFailure`] here is the enum over those constants rather than a second
//! copy of the numbers.

/// Define a code table: the enum, its two conversions, its specification
/// symbol, its one line description, and the list of named values a test can
/// iterate.
///
/// The table is written once and the four matches are generated from it, so a
/// typo cannot put a value in `from_*` and a different one in `to_*`. The
/// round trip test at the bottom of this file proves the pair is an identity
/// over every named value, which is the failure a reader cannot catch: two
/// variants sharing a number look fine on the page.
macro_rules! code_enum {
    (
        $(#[$enum_meta:meta])*
        $name:ident : $repr:ty, $from:ident, $to:ident, $unknown:literal {
            $( $variant:ident = $value:literal, $symbol:literal, $describe:literal; )+
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $(
                #[doc = $describe]
                ///
                #[doc = $symbol]
                $variant,
            )+
            /// A value this build does not know, preserved so it can be
            /// logged, reported as a number, and re-encoded unchanged.
            Unknown($repr),
        }

        impl $name {
            /// Every named value, in specification order. Tests iterate it;
            /// nothing on the hot path does.
            pub const ALL: &'static [Self] = &[ $( Self::$variant, )+ ];

            /// The wire value as this enum, falling through to
            /// [`Self::Unknown`].
            #[must_use]
            pub const fn $from(value: $repr) -> Self {
                match value {
                    $( $value => Self::$variant, )+
                    other => Self::Unknown(other),
                }
            }

            /// The wire value, including an unknown one unchanged.
            #[must_use]
            pub const fn $to(self) -> $repr {
                match self {
                    $( Self::$variant => $value, )+
                    Self::Unknown(value) => value,
                }
            }

            /// The specification's own constant name, for a log line.
            #[must_use]
            pub const fn symbol(self) -> &'static str {
                match self {
                    $( Self::$variant => $symbol, )+
                    Self::Unknown(_) => $unknown,
                }
            }

            /// One line of English, for the user interface.
            #[must_use]
            pub const fn describe(self) -> &'static str {
                match self {
                    $( Self::$variant => $describe, )+
                    Self::Unknown(_) => "A code this client does not recognise.",
                }
            }

            /// False for a value this build has no name for.
            #[must_use]
            pub const fn is_known(self) -> bool {
                !matches!(self, Self::Unknown(_))
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{} ({:#x})", self.symbol(), self.$to())
            }
        }
    };
}

code_enum! {
    /// `errorInfo` of the Set Error Info PDU (MS-RDPBCGR 2.2.5.1.1).
    ///
    /// The most useful four bytes in the protocol: it is how a server says
    /// why it is about to disconnect. Codes from `0x000010C9` upward are the
    /// server telling us that our own PDU was wrong, which makes them the
    /// highest value debugging signal this crate carries and the reason
    /// [`ErrInfo::symbol`] exists at all (PRDRDP/13 §4.10.2).
    ///
    /// The table was transcribed by hand from MS-RDPBCGR 2.2.5.1.1. A value
    /// missing from it decodes as [`ErrInfo::Unknown`] and is reported as a
    /// number, so an omission costs a name in a log line and nothing else.
    ErrInfo: u32, from_u32, to_u32, "ERRINFO_UNKNOWN" {
        None = 0x0000_0000, "ERRINFO_NONE",
            "No error. The server reported no disconnect reason.";
        RpcInitiatedDisconnect = 0x0000_0001, "ERRINFO_RPC_INITIATED_DISCONNECT",
            "An administrative tool disconnected the session.";
        RpcInitiatedLogoff = 0x0000_0002, "ERRINFO_RPC_INITIATED_LOGOFF",
            "An administrative tool logged the session off.";
        IdleTimeout = 0x0000_0003, "ERRINFO_IDLE_TIMEOUT",
            "The session was idle for longer than the server allows.";
        LogonTimeout = 0x0000_0004, "ERRINFO_LOGON_TIMEOUT",
            "The logon took longer than the server allows.";
        DisconnectedByOtherConnection = 0x0000_0005, "ERRINFO_DISCONNECTED_BY_OTHERCONNECTION",
            "Another connection took over this session.";
        OutOfMemory = 0x0000_0006, "ERRINFO_OUT_OF_MEMORY",
            "The server ran out of memory.";
        ServerDeniedConnection = 0x0000_0007, "ERRINFO_SERVER_DENIED_CONNECTION",
            "The server denied the connection.";
        ServerInsufficientPrivileges = 0x0000_0009, "ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES",
            "The account does not have permission to sign in remotely.";
        ServerFreshCredentialsRequired = 0x0000_000a, "ERRINFO_SERVER_FRESH_CREDENTIALS_REQUIRED",
            "The server requires credentials entered again rather than reused.";
        RpcInitiatedDisconnectByUser = 0x0000_000b, "ERRINFO_RPC_INITIATED_DISCONNECT_BYUSER",
            "A user disconnected the session through an administrative tool.";
        LogoffByUser = 0x0000_000c, "ERRINFO_LOGOFF_BY_USER",
            "The user logged off.";
        CloseStackOnDriverNotReady = 0x0000_000f, "ERRINFO_CLOSE_STACK_ON_DRIVER_NOT_READY",
            "The server display driver was not ready.";
        ServerDwmCrash = 0x0000_0010, "ERRINFO_SERVER_DWM_CRASH",
            "The desktop window manager on the server stopped.";
        CloseStackOnDriverFailure = 0x0000_0011, "ERRINFO_CLOSE_STACK_ON_DRIVER_FAILURE",
            "The server display driver failed.";
        CloseStackOnDriverIfaceFailure = 0x0000_0012, "ERRINFO_CLOSE_STACK_ON_DRIVER_IFACE_FAILURE",
            "The server display driver interface failed.";
        ServerWinlogonCrash = 0x0000_0017, "ERRINFO_SERVER_WINLOGON_CRASH",
            "The logon process on the server stopped.";
        ServerCsrssCrash = 0x0000_0018, "ERRINFO_SERVER_CSRSS_CRASH",
            "A core server process stopped.";
        ServerShutdown = 0x0000_0019, "ERRINFO_SERVER_SHUTDOWN",
            "The server is shutting down.";
        ServerReboot = 0x0000_001a, "ERRINFO_SERVER_REBOOT",
            "The server is restarting.";
        LicenseInternal = 0x0000_0100, "ERRINFO_LICENSE_INTERNAL",
            "The server's licensing component failed.";
        LicenseNoLicenseServer = 0x0000_0101, "ERRINFO_LICENSE_NO_LICENSE_SERVER",
            "The server could not reach a licence server.";
        LicenseNoLicense = 0x0000_0102, "ERRINFO_LICENSE_NO_LICENSE",
            "No client access licence is available.";
        LicenseBadClientMsg = 0x0000_0103, "ERRINFO_LICENSE_BAD_CLIENT_MSG",
            "The server rejected a licensing message from this client.";
        LicenseHwidDoesntMatchLicense = 0x0000_0104, "ERRINFO_LICENSE_HWID_DOESNT_MATCH_LICENSE",
            "The stored licence belongs to different hardware.";
        LicenseBadClientLicense = 0x0000_0105, "ERRINFO_LICENSE_BAD_CLIENT_LICENSE",
            "The licence this client presented is not valid.";
        LicenseCantFinishProtocol = 0x0000_0106, "ERRINFO_LICENSE_CANT_FINISH_PROTOCOL",
            "The licensing exchange could not be completed.";
        LicenseClientEndedProtocol = 0x0000_0107, "ERRINFO_LICENSE_CLIENT_ENDED_PROTOCOL",
            "The client ended the licensing exchange.";
        LicenseBadClientEncryption = 0x0000_0108, "ERRINFO_LICENSE_BAD_CLIENT_ENCRYPTION",
            "The server could not decrypt a licensing message from this client.";
        LicenseCantUpgradeLicense = 0x0000_0109, "ERRINFO_LICENSE_CANT_UPGRADE_LICENSE",
            "The stored licence could not be upgraded.";
        LicenseNoRemoteConnections = 0x0000_010a, "ERRINFO_LICENSE_NO_REMOTE_CONNECTIONS",
            "The server does not accept remote connections.";
        CbDestinationNotFound = 0x0000_0400, "ERRINFO_CB_DESTINATION_NOT_FOUND",
            "The connection broker could not find the target computer.";
        CbLoadingDestination = 0x0000_0402, "ERRINFO_CB_LOADING_DESTINATION",
            "The target computer is still starting.";
        CbRedirectingToDestination = 0x0000_0404, "ERRINFO_CB_REDIRECTING_TO_DESTINATION",
            "The connection broker is redirecting to another computer.";
        CbSessionOnlineVmWake = 0x0000_0405, "ERRINFO_CB_SESSION_ONLINE_VM_WAKE",
            "The target virtual machine is being woken.";
        CbSessionOnlineVmBoot = 0x0000_0406, "ERRINFO_CB_SESSION_ONLINE_VM_BOOT",
            "The target virtual machine is starting.";
        CbSessionOnlineVmNoDns = 0x0000_0407, "ERRINFO_CB_SESSION_ONLINE_VM_NO_DNS",
            "The target virtual machine has no name in DNS yet.";
        CbDestinationPoolNotFree = 0x0000_0408, "ERRINFO_CB_DESTINATION_POOL_NOT_FREE",
            "No computer in the pool is free.";
        CbConnectionCancelled = 0x0000_0409, "ERRINFO_CB_CONNECTION_CANCELLED",
            "The connection was cancelled.";
        CbConnectionErrorInvalidSettings = 0x0000_0410, "ERRINFO_CB_CONNECTION_ERROR_INVALID_SETTINGS",
            "The connection settings the broker was given are not valid.";
        CbSessionOnlineVmBootTimeout = 0x0000_0411, "ERRINFO_CB_SESSION_ONLINE_VM_BOOT_TIMEOUT",
            "The target virtual machine took too long to start.";
        CbSessionOnlineVmSessmonFailed = 0x0000_0412, "ERRINFO_CB_SESSION_ONLINE_VM_SESSMON_FAILED",
            "The session monitor on the target virtual machine failed.";
        UnknownPduType2 = 0x0000_10c9, "ERRINFO_UNKNOWNPDUTYPE2",
            "The server did not recognise a share data PDU this client sent.";
        UnknownPduType = 0x0000_10ca, "ERRINFO_UNKNOWNPDUTYPE",
            "The server did not recognise a share control PDU this client sent.";
        DataPduSequence = 0x0000_10cb, "ERRINFO_DATAPDUSEQUENCE",
            "This client sent a share data PDU out of order.";
        ControlPduSequence = 0x0000_10cd, "ERRINFO_CONTROLPDUSEQUENCE",
            "This client sent a control PDU out of order.";
        InvalidControlPduAction = 0x0000_10ce, "ERRINFO_INVALIDCONTROLPDUACTION",
            "This client sent a control PDU with an invalid action.";
        InvalidInputPduType = 0x0000_10cf, "ERRINFO_INVALIDINPUTPDUTYPE",
            "This client sent an input event of an invalid type.";
        InvalidInputPduMouse = 0x0000_10d0, "ERRINFO_INVALIDINPUTPDUMOUSE",
            "This client sent an invalid mouse event.";
        InvalidRefreshRectPdu = 0x0000_10d1, "ERRINFO_INVALIDREFRESHRECTPDU",
            "This client sent an invalid Refresh Rect PDU.";
        CreateUserDataFailed = 0x0000_10d2, "ERRINFO_CREATEUSERDATAFAILED",
            "The server could not build its user data from ours.";
        ConnectFailed = 0x0000_10d3, "ERRINFO_CONNECTFAILED",
            "The server could not complete the connection.";
        ConfirmActiveWrongShareId = 0x0000_10d4, "ERRINFO_CONFIRMACTIVEWRONGSHAREID",
            "The Confirm Active PDU echoed the wrong share identifier.";
        ConfirmActiveWrongOriginator = 0x0000_10d5, "ERRINFO_CONFIRMACTIVEWRONGORIGINATOR",
            "The Confirm Active PDU carried the wrong originator identifier.";
        PersistentKeyPduBadLength = 0x0000_10da, "ERRINFO_PERSISTENTKEYPDUBADLENGTH",
            "The Persistent Key List PDU had the wrong length.";
        PersistentKeyPduIllegalFirst = 0x0000_10db, "ERRINFO_PERSISTENTKEYPDUILLEGALFIRST",
            "The first Persistent Key List PDU was not marked as first.";
        PersistentKeyPduTooManyTotalKeys = 0x0000_10dc, "ERRINFO_PERSISTENTKEYPDUTOOMANYTOTALKEYS",
            "The Persistent Key List PDU declared too many keys in total.";
        PersistentKeyPduTooManyCacheKeys = 0x0000_10dd, "ERRINFO_PERSISTENTKEYPDUTOOMANYCACHEKEYS",
            "The Persistent Key List PDU declared too many keys in one cache.";
        InputPduBadLength = 0x0000_10de, "ERRINFO_INPUTPDUBADLENGTH",
            "An input PDU from this client had the wrong length.";
        BitmapCacheErrorPduBadLength = 0x0000_10df, "ERRINFO_BITMAPCACHEERRORPDUBADLENGTH",
            "A Bitmap Cache Error PDU had the wrong length.";
        SecurityDataTooShort = 0x0000_10e0, "ERRINFO_SECURITYDATATOOSHORT",
            "A PDU from this client was shorter than its security header claimed.";
        VChannelDataTooShort = 0x0000_10e1, "ERRINFO_VCHANNELDATATOOSHORT",
            "A virtual channel PDU from this client was too short.";
        ShareDataTooShort = 0x0000_10e2, "ERRINFO_SHAREDATATOOSHORT",
            "A share data PDU from this client was too short.";
        BadSuppressOutputPdu = 0x0000_10e3, "ERRINFO_BADSUPRESSOUTPUTPDU",
            "This client sent an invalid Suppress Output PDU.";
        ConfirmActivePduTooShort = 0x0000_10e5, "ERRINFO_CONFIRMACTIVEPDUTOOSHORT",
            "The Confirm Active PDU was too short.";
        CapabilitySetTooSmall = 0x0000_10e7, "ERRINFO_CAPABILITYSETTOOSMALL",
            "A capability set this client sent was too small.";
        CapabilitySetTooLarge = 0x0000_10e8, "ERRINFO_CAPABILITYSETTOOLARGE",
            "A capability set this client sent was too large.";
        NoCursorCache = 0x0000_10e9, "ERRINFO_NOCURSORCACHE",
            "The client advertised no usable pointer cache.";
        BadCapabilities = 0x0000_10ea, "ERRINFO_BADCAPABILITIES",
            "The server rejected this client's capability sets.";
        VirtualChannelDecompressionErr = 0x0000_10ec, "ERRINFO_VIRTUALCHANNELDECOMPRESSIONERR",
            "The server could not decompress a virtual channel PDU from this client.";
        InvalidVcCompressionType = 0x0000_10ed, "ERRINFO_INVALIDVCCOMPRESSIONTYPE",
            "This client used a virtual channel compression type the server rejects.";
        InvalidChannelId = 0x0000_10ef, "ERRINFO_INVALIDCHANNELID",
            "This client used a channel identifier the server does not know.";
        VChannelsTooMany = 0x0000_10f0, "ERRINFO_VCHANNELSTOOMANY",
            "This client asked for more virtual channels than the server allows.";
        RemoteAppsNotEnabled = 0x0000_10f3, "ERRINFO_REMOTEAPPSNOTENABLED",
            "RemoteApp is not enabled on the server.";
        CacheCapNotSet = 0x0000_10f4, "ERRINFO_CACHECAPNOTSET",
            "The client used a cache it had not advertised.";
        BitmapCacheErrorPduBadLength2 = 0x0000_10f5, "ERRINFO_BITMAPCACHEERRORPDUBADLENGTH2",
            "A Bitmap Cache Error PDU had the wrong length.";
        OffscrCacheErrorPduBadLength = 0x0000_10f6, "ERRINFO_OFFSCRCACHEERRORPDUBADLENGTH",
            "An Offscreen Cache Error PDU had the wrong length.";
        DngCacheErrorPduBadLength = 0x0000_10f7, "ERRINFO_DNGCACHEERRORPDUBADLENGTH",
            "A DrawNineGrid Cache Error PDU had the wrong length.";
        GdiPlusPduBadLength = 0x0000_10f8, "ERRINFO_GDIPLUSPDUBADLENGTH",
            "A GDI+ Error PDU had the wrong length.";
        SecurityDataTooShort2 = 0x0000_1111, "ERRINFO_SECURITYDATATOOSHORT2",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort3 = 0x0000_1112, "ERRINFO_SECURITYDATATOOSHORT3",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort4 = 0x0000_1113, "ERRINFO_SECURITYDATATOOSHORT4",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort5 = 0x0000_1114, "ERRINFO_SECURITYDATATOOSHORT5",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort6 = 0x0000_1115, "ERRINFO_SECURITYDATATOOSHORT6",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort7 = 0x0000_1116, "ERRINFO_SECURITYDATATOOSHORT7",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort8 = 0x0000_1117, "ERRINFO_SECURITYDATATOOSHORT8",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort9 = 0x0000_1118, "ERRINFO_SECURITYDATATOOSHORT9",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort10 = 0x0000_1119, "ERRINFO_SECURITYDATATOOSHORT10",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort11 = 0x0000_111a, "ERRINFO_SECURITYDATATOOSHORT11",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort12 = 0x0000_111b, "ERRINFO_SECURITYDATATOOSHORT12",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort13 = 0x0000_111c, "ERRINFO_SECURITYDATATOOSHORT13",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort14 = 0x0000_111d, "ERRINFO_SECURITYDATATOOSHORT14",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort15 = 0x0000_111e, "ERRINFO_SECURITYDATATOOSHORT15",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort16 = 0x0000_111f, "ERRINFO_SECURITYDATATOOSHORT16",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort17 = 0x0000_1120, "ERRINFO_SECURITYDATATOOSHORT17",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort18 = 0x0000_1121, "ERRINFO_SECURITYDATATOOSHORT18",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort19 = 0x0000_1122, "ERRINFO_SECURITYDATATOOSHORT19",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort20 = 0x0000_1123, "ERRINFO_SECURITYDATATOOSHORT20",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort21 = 0x0000_1124, "ERRINFO_SECURITYDATATOOSHORT21",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort22 = 0x0000_1125, "ERRINFO_SECURITYDATATOOSHORT22",
            "A PDU from this client was too short for its security header.";
        SecurityDataTooShort23 = 0x0000_1126, "ERRINFO_SECURITYDATATOOSHORT23",
            "A PDU from this client was too short for its security header.";
        BadMonitorData = 0x0000_1129, "ERRINFO_BADMONITORDATA",
            "The monitor layout this client sent is not valid.";
        VcDecompressedReassembleFailed = 0x0000_112a, "ERRINFO_VCDECOMPRESSEDREASSEMBLEFAILED",
            "The server could not reassemble a decompressed virtual channel message.";
        VcDataTooLong = 0x0000_112b, "ERRINFO_VCDATATOOLONG",
            "A virtual channel message from this client was too long.";
        BadFrameAckData = 0x0000_112c, "ERRINFO_BAD_FRAME_ACK_DATA",
            "A frame acknowledge PDU from this client was not valid.";
        GraphicsModeNotSupported = 0x0000_112d, "ERRINFO_GRAPHICSMODENOTSUPPORTED",
            "The server does not support the requested graphics mode.";
        GraphicsSubsystemResetFailed = 0x0000_112e, "ERRINFO_GRAPHICSSUBSYSTEMRESETFAILED",
            "The server could not reset its graphics subsystem.";
        GraphicsSubsystemFailed = 0x0000_112f, "ERRINFO_GRAPHICSSUBSYSTEMFAILED",
            "The graphics subsystem on the server failed.";
        TimezoneKeyNameLengthTooShort = 0x0000_1130, "ERRINFO_TIMEZONEKEYNAMELENGTHTOOSHORT",
            "The dynamic time zone key name this client sent was too short.";
        TimezoneKeyNameLengthTooLong = 0x0000_1131, "ERRINFO_TIMEZONEKEYNAMELENGTHTOOLONG",
            "The dynamic time zone key name this client sent was too long.";
        DynamicDstDisabledFieldMissing = 0x0000_1132, "ERRINFO_DYNAMICDSTDISABLEDFIELDMISSING",
            "The client info PDU was missing the dynamic daylight saving field.";
        VcDecodingError = 0x0000_1133, "ERRINFO_VCDECODINGERROR",
            "The server could not decode a virtual channel message.";
        VirtualDesktopTooLarge = 0x0000_1134, "ERRINFO_VIRTUALDESKTOPTOOLARGE",
            "The requested virtual desktop is larger than the server allows.";
        MonitorGeometryValidationFailed = 0x0000_1135, "ERRINFO_MONITORGEOMETRYVALIDATIONFAILED",
            "The monitor geometry this client sent failed validation.";
        InvalidMonitorCount = 0x0000_1136, "ERRINFO_INVALIDMONITORCOUNT",
            "This client asked for a number of monitors the server rejects.";
        UpdateSessionKeyFailed = 0x0000_1191, "ERRINFO_UPDATESESSIONKEYFAILED",
            "The server could not update the session key.";
        DecryptFailed = 0x0000_1192, "ERRINFO_DECRYPTFAILED",
            "The server could not decrypt a PDU from this client.";
        EncryptFailed = 0x0000_1193, "ERRINFO_ENCRYPTFAILED",
            "The server could not encrypt a PDU for this client.";
        EncPkgMismatch = 0x0000_1194, "ERRINFO_ENCPKGMISMATCH",
            "The client and server disagree about the encryption package.";
        DecryptFailed2 = 0x0000_1195, "ERRINFO_DECRYPTFAILED2",
            "The server could not decrypt a PDU from this client.";
    }
}

impl ErrInfo {
    /// True for the codes of `0x000010C9` upward, which are the server saying
    /// that a PDU we sent was wrong (PRDRDP/13 §4.10.2).
    ///
    /// A log line that says so is worth writing, because these are the only
    /// ERRINFO codes that point at our own bug rather than at the server's
    /// state.
    #[must_use]
    pub const fn is_our_protocol_error(self) -> bool {
        self.to_u32() >= 0x0000_10c9
    }
}

// The enum is generated by `code_enum!`, so `#[default]` cannot be attached
// to one of its variants from out here and the impl is written by hand.
#[allow(clippy::derivable_impls)]
impl Default for ErrInfo {
    fn default() -> Self {
        Self::None
    }
}

code_enum! {
    /// `RDP_NEG_FAILURE.failureCode` (MS-RDPBCGR 2.2.1.2.2).
    ///
    /// The values themselves live in
    /// [`x224::neg_failure`](crate::x224::neg_failure), which `x224.rs`
    /// declared before this module existed; this enum is over those numbers
    /// rather than a second copy of them, and the test at the bottom of this
    /// file asserts the two agree.
    NegFailure: u32, from_u32, to_u32, "RDP_NEG_FAILURE_UNKNOWN" {
        SslRequiredByServer = 0x0000_0001, "SSL_REQUIRED_BY_SERVER",
            "The server requires TLS and this connection did not offer it.";
        SslNotAllowedByServer = 0x0000_0002, "SSL_NOT_ALLOWED_BY_SERVER",
            "The server refuses TLS and requires the legacy RDP security layer.";
        SslCertNotOnServer = 0x0000_0003, "SSL_CERT_NOT_ON_SERVER",
            "The server has no certificate it can use for TLS.";
        InconsistentFlags = 0x0000_0004, "INCONSISTENT_FLAGS",
            "The server rejected the combination of flags in the request.";
        HybridRequiredByServer = 0x0000_0005, "HYBRID_REQUIRED_BY_SERVER",
            "The server requires network level authentication.";
        SslWithUserAuthRequiredByServer = 0x0000_0006, "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
            "The server requires network level authentication and a trusted certificate.";
    }
}

impl NegFailure {
    /// Whether re-dialling with a different `requestedProtocols` could
    /// succeed, and with which protocol (PRDRDP/13 §8).
    ///
    /// This is the one place a code table drives a protocol decision rather
    /// than a message. `SSL_NOT_ALLOWED_BY_SERVER` means "try
    /// `PROTOCOL_RDP`", which PRDRDP/03 §13.1 refuses, so the hint is
    /// [`None`] for it. Whether we take a hint we are given is PRDRDP/03's
    /// NLA policy, not ours.
    #[must_use]
    pub const fn retry_hint(self) -> Option<u32> {
        match self {
            Self::SslRequiredByServer => Some(crate::x224::security_protocol::SSL),
            Self::HybridRequiredByServer | Self::SslWithUserAuthRequiredByServer => {
                Some(crate::x224::security_protocol::HYBRID)
            }
            _ => None,
        }
    }
}

code_enum! {
    /// `LICENSE_ERROR_MESSAGE.dwErrorCode` (MS-RDPBCGR 2.2.1.12.1.3).
    LicenseError: u32, from_u32, to_u32, "LICENSE_ERROR_UNKNOWN" {
        InvalidServerCertificate = 0x0000_0001, "ERR_INVALID_SERVER_CERTIFICATE",
            "The server's licensing certificate is not valid.";
        NoLicense = 0x0000_0002, "ERR_NO_LICENSE",
            "The server has no client access licence to issue.";
        InvalidMac = 0x0000_0003, "ERR_INVALID_MAC",
            "A licensing message failed its integrity check.";
        InvalidScope = 0x0000_0004, "ERR_INVALID_SCOPE",
            "The licence scope the server offered is not one this client accepts.";
        NoLicenseServer = 0x0000_0006, "ERR_NO_LICENSE_SERVER",
            "The server could not reach a licence server.";
        StatusValidClient = 0x0000_0007, "STATUS_VALID_CLIENT",
            "No licence is required; the connection may continue.";
        InvalidClient = 0x0000_0008, "ERR_INVALID_CLIENT",
            "The client declined the licensing exchange.";
        InvalidProductId = 0x0000_000b, "ERR_INVALID_PRODUCTID",
            "The product identifier in a licensing message is not valid.";
        InvalidMessageLen = 0x0000_000c, "ERR_INVALID_MESSAGE_LEN",
            "A licensing message had the wrong length.";
    }
}

code_enum! {
    /// `LICENSE_ERROR_MESSAGE.dwStateTransition` (MS-RDPBCGR 2.2.1.12.1.3).
    LicenseStateTransition: u32, from_u32, to_u32, "ST_UNKNOWN" {
        TotalAbort = 0x0000_0001, "ST_TOTAL_ABORT",
            "Abandon the licensing exchange and the connection with it.";
        NoTransition = 0x0000_0002, "ST_NO_TRANSITION",
            "Stay where you are; nothing further is required.";
        ResetPhaseToStart = 0x0000_0003, "ST_RESET_PHASE_TO_START",
            "Restart the licensing exchange from the beginning.";
        ResendLastMessage = 0x0000_0004, "ST_RESEND_LAST_MESSAGE",
            "Send the previous licensing message again.";
    }
}

code_enum! {
    /// `TS_LOGON_ERRORS_INFO.ErrorNotificationType` (MS-RDPBCGR
    /// 2.2.10.1.1.4.1).
    LogonErrorType: u32, from_u32, to_u32, "LOGON_ERROR_UNKNOWN" {
        FailedBadPassword = 0x0000_0000, "LOGON_FAILED_BAD_PASSWORD",
            "The user name or password is not correct.";
        FailedUpdatePassword = 0x0000_0001, "LOGON_FAILED_UPDATE_PASSWORD",
            "The password must be changed before signing in.";
        FailedOther = 0x0000_0002, "LOGON_FAILED_OTHER",
            "The sign in failed.";
        Warning = 0x0000_0003, "LOGON_WARNING",
            "The server sent a warning about the sign in.";
    }
}

code_enum! {
    /// `TS_LOGON_ERRORS_INFO.ErrorNotificationData` (MS-RDPBCGR
    /// 2.2.10.1.1.4.1).
    ///
    /// Anything outside this table is a Windows status code, so
    /// [`LogonErrorData::Unknown`] is the common case here and is not an
    /// error (PRDRDP/13 §8).
    LogonErrorData: u32, from_u32, to_u32, "LOGON_MSG_NTSTATUS" {
        DisconnectRefused = 0xffff_fff9, "LOGON_MSG_DISCONNECT_REFUSED",
            "The server refused to disconnect the other session.";
        NoPermission = 0xffff_fffa, "LOGON_MSG_NO_PERMISSION",
            "The account does not have permission to sign in.";
        BumpOptions = 0xffff_fffb, "LOGON_MSG_BUMP_OPTIONS",
            "The server is asking whether to disconnect another session.";
        ReconnectOptions = 0xffff_fffc, "LOGON_MSG_RECONNECT_OPTIONS",
            "The server is asking which session to reconnect to.";
        SessionTerminate = 0xffff_fffd, "LOGON_MSG_SESSION_TERMINATE",
            "The session is being ended.";
        SessionContinue = 0xffff_fffe, "LOGON_MSG_SESSION_CONTINUE",
            "The session is continuing.";
    }
}

code_enum! {
    /// `Server Initiate Multitransport Request.requestedProtocol`
    /// (MS-RDPBCGR 2.2.15.1).
    ///
    /// Two values, both UDP, and this client asks for neither: the Client
    /// Multitransport Channel Data block goes out with `flags = 0`, which
    /// says the client understands multitransport bootstrapping and wants no
    /// side channel (PRDRDP/03 §2.9). The table is here so that a server
    /// which sends a request anyway is refused by name in a log line rather
    /// than by a bare number, which is the whole point of this file.
    MultitransportProtocol: u16, from_u16, to_u16, "INITIATE_REQUEST_PROTOCOL_UNKNOWN" {
        UdpFecR = 0x0001, "INITIATE_REQUEST_PROTOCOL_UDPFECR",
            "A reliable UDP transport, for the graphics channel.";
        UdpFecL = 0x0002, "INITIATE_REQUEST_PROTOCOL_UDPFECL",
            "A lossy UDP transport, for audio and input.";
    }
}

code_enum! {
    /// The compression type in the low four bits of any compression flags
    /// field (MS-RDPBCGR 3.1.8, PRDRDP/13 §7).
    ///
    /// This crate reads the type and the two lengths; the history buffers and
    /// the decompressors are `rdp-codecs`'. Phase 1 advertises no compression
    /// at all, and parses the headers anyway, because a server may compress
    /// despite the advertisement and a clear error beats a garbled screen.
    CompressionType: u8, from_u8, to_u8, "PACKET_COMPR_TYPE_UNKNOWN" {
        Mppc8K = 0x00, "PACKET_COMPR_TYPE_8K",
            "MPPC with an 8 KiB history buffer.";
        Mppc64K = 0x01, "PACKET_COMPR_TYPE_64K",
            "MPPC with a 64 KiB history buffer.";
        Rdp6 = 0x02, "PACKET_COMPR_TYPE_RDP6",
            "The RDP 6.0 bulk compressor.";
        Rdp61 = 0x03, "PACKET_COMPR_TYPE_RDP61",
            "The RDP 6.1 bulk compressor.";
        Rdp8 = 0x04, "PACKET_COMPR_TYPE_RDP8",
            "The RDP 8.0 bulk compressor.";
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

    use super::*;
    use std::collections::HashSet;

    /// The property PRDRDP/13 §8 asks for, over every named value and over a
    /// sample of the unknown space. Two variants mapping to the same number
    /// is the typo a reader does not catch and this does.
    #[test]
    fn every_code_round_trips_through_its_wire_value() {
        for code in ErrInfo::ALL {
            assert_eq!(ErrInfo::from_u32(code.to_u32()), *code, "{}", code.symbol());
        }
        for code in NegFailure::ALL {
            assert_eq!(NegFailure::from_u32(code.to_u32()), *code);
        }
        for code in LicenseError::ALL {
            assert_eq!(LicenseError::from_u32(code.to_u32()), *code);
        }
        for code in LicenseStateTransition::ALL {
            assert_eq!(LicenseStateTransition::from_u32(code.to_u32()), *code);
        }
        for code in LogonErrorType::ALL {
            assert_eq!(LogonErrorType::from_u32(code.to_u32()), *code);
        }
        for code in LogonErrorData::ALL {
            assert_eq!(LogonErrorData::from_u32(code.to_u32()), *code);
        }
        for code in CompressionType::ALL {
            assert_eq!(CompressionType::from_u8(code.to_u8()), *code);
        }
        for code in MultitransportProtocol::ALL {
            assert_eq!(MultitransportProtocol::from_u16(code.to_u16()), *code);
        }
    }

    /// An unknown value survives the round trip unchanged, which is what lets
    /// a code from a newer Windows reach the user as a number.
    #[test]
    fn an_unknown_value_is_preserved_rather_than_lost() {
        for value in [0x0000_2000_u32, 0x1234_5678, 0xffff_0000, 0x0000_000d] {
            let code = ErrInfo::from_u32(value);
            assert_eq!(code, ErrInfo::Unknown(value));
            assert_eq!(code.to_u32(), value);
            assert!(!code.is_known());
        }
        assert_eq!(CompressionType::from_u8(0x0f).to_u8(), 0x0f);
    }

    /// Sampling the whole `u32` space in the shape PRDRDP/13 §9.5 describes,
    /// without the proptest dependency: every value the table does not name
    /// must come back as itself.
    #[test]
    fn the_unknown_fallthrough_is_an_identity_over_a_sampled_range() {
        let named: HashSet<u32> = ErrInfo::ALL.iter().map(|c| c.to_u32()).collect();
        let mut value: u32 = 0;
        for _ in 0..5000 {
            if !named.contains(&value) {
                assert_eq!(ErrInfo::from_u32(value), ErrInfo::Unknown(value));
            }
            assert_eq!(ErrInfo::from_u32(value).to_u32(), value);
            // A cheap spread over the space rather than the first 5000
            // integers, which would only exercise two of the five ranges.
            value = value.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        }
    }

    /// No two variants share a number, stated directly rather than inferred
    /// from the round trip.
    #[test]
    fn no_two_errinfo_variants_share_a_value() {
        let mut seen = HashSet::new();
        for code in ErrInfo::ALL {
            assert!(
                seen.insert(code.to_u32()),
                "duplicate value {}",
                code.symbol()
            );
        }
        let mut symbols = HashSet::new();
        for code in ErrInfo::ALL {
            assert!(
                symbols.insert(code.symbol()),
                "duplicate symbol {}",
                code.symbol()
            );
        }
    }

    /// The protocol error range is the one worth naming in a log line.
    #[test]
    fn the_protocol_error_range_is_recognised() {
        assert!(ErrInfo::UnknownPduType2.is_our_protocol_error());
        assert!(ErrInfo::DecryptFailed2.is_our_protocol_error());
        assert!(!ErrInfo::LogoffByUser.is_our_protocol_error());
        assert!(!ErrInfo::CbDestinationNotFound.is_our_protocol_error());
    }

    /// This enum and `x224.rs` must not drift apart.
    #[test]
    fn neg_failure_agrees_with_the_x224_constants() {
        use crate::x224::neg_failure;
        assert_eq!(
            NegFailure::SslRequiredByServer.to_u32(),
            neg_failure::SSL_REQUIRED_BY_SERVER
        );
        assert_eq!(
            NegFailure::SslNotAllowedByServer.to_u32(),
            neg_failure::SSL_NOT_ALLOWED_BY_SERVER
        );
        assert_eq!(
            NegFailure::SslCertNotOnServer.to_u32(),
            neg_failure::SSL_CERT_NOT_ON_SERVER
        );
        assert_eq!(
            NegFailure::InconsistentFlags.to_u32(),
            neg_failure::INCONSISTENT_FLAGS
        );
        assert_eq!(
            NegFailure::HybridRequiredByServer.to_u32(),
            neg_failure::HYBRID_REQUIRED_BY_SERVER
        );
        assert_eq!(
            NegFailure::SslWithUserAuthRequiredByServer.to_u32(),
            neg_failure::SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER
        );
    }

    /// The one hint that drives a decision rather than a message.
    #[test]
    fn the_retry_hint_names_only_protocols_we_will_dial() {
        assert_eq!(
            NegFailure::HybridRequiredByServer.retry_hint(),
            Some(crate::x224::security_protocol::HYBRID)
        );
        assert_eq!(
            NegFailure::SslRequiredByServer.retry_hint(),
            Some(crate::x224::security_protocol::SSL)
        );
        // PRDRDP/03 §13.1 refuses standard RDP security, so there is no hint.
        assert_eq!(NegFailure::SslNotAllowedByServer.retry_hint(), None);
        assert_eq!(NegFailure::Unknown(0x99).retry_hint(), None);
    }

    /// `Display` is what a log line uses and it carries both halves.
    #[test]
    fn display_names_the_symbol_and_the_number() {
        assert_eq!(
            ErrInfo::LogoffByUser.to_string(),
            "ERRINFO_LOGOFF_BY_USER (0xc)"
        );
        assert_eq!(
            ErrInfo::Unknown(0x4242).to_string(),
            "ERRINFO_UNKNOWN (0x4242)"
        );
    }

    /// Every description is a sentence a user interface can show.
    #[test]
    fn every_description_is_present_and_ends_in_a_full_stop() {
        for code in ErrInfo::ALL {
            let text = code.describe();
            assert!(!text.is_empty(), "{}", code.symbol());
            assert!(text.ends_with('.'), "{}: {text}", code.symbol());
        }
    }
}
