#[cfg(feature = "lab")]
use std::ffi::OsStr;

#[cfg_attr(not(feature = "lab"), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildMode {
    Normal,
    InsufficientLandlockAbi,
    RestrictionProbeFailure,
    SeccompInstallationFailure,
    UnknownAncillary,
    StallAt(StallPoint),
    ExitAt(FaultPoint),
}

impl ChildMode {
    #[cfg(feature = "lab")]
    pub(crate) fn argument(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::InsufficientLandlockAbi => "insufficient-landlock-abi",
            Self::RestrictionProbeFailure => "restriction-probe-failure",
            Self::SeccompInstallationFailure => "seccomp-installation-failure",
            Self::UnknownAncillary => "unknown-ancillary",
            Self::StallAt(point) => point.argument(),
            Self::ExitAt(point) => point.argument(),
        }
    }

    #[cfg(feature = "lab")]
    pub(crate) fn parse(argument: &OsStr) -> Option<Self> {
        let argument = argument.to_str()?;
        match argument {
            "normal" => Some(Self::Normal),
            "insufficient-landlock-abi" => Some(Self::InsufficientLandlockAbi),
            "restriction-probe-failure" => Some(Self::RestrictionProbeFailure),
            "seccomp-installation-failure" => Some(Self::SeccompInstallationFailure),
            "unknown-ancillary" => Some(Self::UnknownAncillary),
            _ => StallPoint::parse(argument)
                .map(Self::StallAt)
                .or_else(|| FaultPoint::parse(argument).map(Self::ExitAt)),
        }
    }

    #[cfg(feature = "lab")]
    pub(crate) fn exit_at(self, point: FaultPoint) {
        if self == Self::ExitAt(point) {
            // SAFETY: this is a deliberate conformance-only abrupt exit. It
            // bypasses destructors so the supervisor must prove process reap
            // before authorizing fixture cleanup.
            unsafe { libc::_exit(point.exit_code()) }
        }
    }

    #[cfg(not(feature = "lab"))]
    pub(crate) fn exit_at(self, _point: FaultPoint) {}

    #[cfg(feature = "lab")]
    pub(crate) fn stall_at(self, point: StallPoint) {
        if self == Self::StallAt(point) {
            loop {
                // SAFETY: pause has no memory contract and returns only after
                // signal delivery. The conformance supervisor owns bounded
                // SIGKILL termination for this deliberate stalled child.
                let _ = unsafe { libc::pause() };
            }
        }
    }

    #[cfg(not(feature = "lab"))]
    pub(crate) fn stall_at(self, _point: StallPoint) {}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StallPoint {
    BootstrapReceive,
    RestrictionSetup,
    RestrictedReady,
    SourceReceive,
    SourceAcceptance,
    PlanReceive,
    PlanAcceptance,
    ProceedReceive,
    ProbeExecution,
    ExitAckReceive,
    ExitCompletion,
}

impl StallPoint {
    #[cfg(feature = "lab")]
    pub(crate) const ALL: [Self; 11] = [
        Self::BootstrapReceive,
        Self::RestrictionSetup,
        Self::RestrictedReady,
        Self::SourceReceive,
        Self::SourceAcceptance,
        Self::PlanReceive,
        Self::PlanAcceptance,
        Self::ProceedReceive,
        Self::ProbeExecution,
        Self::ExitAckReceive,
        Self::ExitCompletion,
    ];

    #[cfg(feature = "lab")]
    pub(crate) const fn argument(self) -> &'static str {
        match self {
            Self::BootstrapReceive => "stall-before-bootstrap-receive",
            Self::RestrictionSetup => "stall-before-restriction-setup",
            Self::RestrictedReady => "stall-before-restriction-ready",
            Self::SourceReceive => "stall-before-source-receive",
            Self::SourceAcceptance => "stall-before-source-acceptance",
            Self::PlanReceive => "stall-before-plan-receive",
            Self::PlanAcceptance => "stall-before-plan-acceptance",
            Self::ProceedReceive => "stall-before-proceed-receive",
            Self::ProbeExecution => "stall-before-probe-execution",
            Self::ExitAckReceive => "stall-before-exit-ack-receive",
            Self::ExitCompletion => "stall-before-exit-completion",
        }
    }

    #[cfg(feature = "lab")]
    fn parse(argument: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|point| point.argument() == argument)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
#[cfg_attr(not(feature = "lab"), allow(dead_code))]
pub(crate) enum FaultPoint {
    ExecEntry = 1,
    PeerValidation = 2,
    InheritedClosure = 3,
    BootstrapReceive = 4,
    StageValidation = 5,
    NoNewPrivs = 6,
    Landlock = 7,
    Seccomp = 8,
    Ready = 9,
    SourceReceive = 10,
    SourceValidation = 11,
    Accepted = 12,
    Proceed = 13,
    SourceProbe = 14,
    OutsideDenial = 15,
    StageCreate = 16,
    Result = 17,
    ExitAck = 18,
    PlanReceive = 19,
    PlanValidation = 20,
    PlanAccepted = 21,
    CompletionSeal = 22,
}

impl FaultPoint {
    #[cfg(feature = "lab")]
    pub(crate) const ALL: [Self; 22] = [
        Self::ExecEntry,
        Self::PeerValidation,
        Self::InheritedClosure,
        Self::BootstrapReceive,
        Self::StageValidation,
        Self::NoNewPrivs,
        Self::Landlock,
        Self::Seccomp,
        Self::Ready,
        Self::SourceReceive,
        Self::SourceValidation,
        Self::Accepted,
        Self::Proceed,
        Self::SourceProbe,
        Self::OutsideDenial,
        Self::StageCreate,
        Self::Result,
        Self::ExitAck,
        Self::PlanReceive,
        Self::PlanValidation,
        Self::PlanAccepted,
        Self::CompletionSeal,
    ];

    #[cfg(feature = "lab")]
    pub(crate) fn argument(self) -> &'static str {
        match self {
            Self::ExecEntry => "exit-after-exec-entry",
            Self::PeerValidation => "exit-after-peer-validation",
            Self::InheritedClosure => "exit-after-inherited-closure",
            Self::BootstrapReceive => "exit-after-bootstrap-receive",
            Self::StageValidation => "exit-after-stage-validation",
            Self::NoNewPrivs => "exit-after-no-new-privs",
            Self::Landlock => "exit-after-landlock",
            Self::Seccomp => "exit-after-seccomp",
            Self::Ready => "exit-after-ready",
            Self::SourceReceive => "exit-after-source-receive",
            Self::SourceValidation => "exit-after-source-validation",
            Self::Accepted => "exit-after-accepted",
            Self::Proceed => "exit-after-proceed",
            Self::SourceProbe => "exit-after-source-probe",
            Self::OutsideDenial => "exit-after-outside-denial",
            Self::StageCreate => "exit-after-stage-create",
            Self::Result => "exit-after-result",
            Self::ExitAck => "exit-after-exit-ack",
            Self::PlanReceive => "exit-after-plan-receive",
            Self::PlanValidation => "exit-after-plan-validation",
            Self::PlanAccepted => "exit-after-plan-accepted",
            Self::CompletionSeal => "exit-after-completion-seal",
        }
    }

    #[cfg(feature = "lab")]
    fn parse(argument: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|point| point.argument() == argument)
    }

    #[cfg(feature = "lab")]
    pub(crate) const fn exit_code(self) -> i32 {
        100 + self as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_child_mode_argument_is_canonical() {
        for mode in [
            ChildMode::Normal,
            ChildMode::InsufficientLandlockAbi,
            ChildMode::RestrictionProbeFailure,
            ChildMode::SeccompInstallationFailure,
            ChildMode::UnknownAncillary,
        ] {
            assert_eq!(ChildMode::parse(OsStr::new(mode.argument())), Some(mode));
        }
        for point in StallPoint::ALL {
            let mode = ChildMode::StallAt(point);
            assert_eq!(ChildMode::parse(OsStr::new(mode.argument())), Some(mode));
        }
        for point in FaultPoint::ALL {
            let mode = ChildMode::ExitAt(point);
            assert_eq!(ChildMode::parse(OsStr::new(mode.argument())), Some(mode));
        }
        assert_eq!(ChildMode::parse(OsStr::new("")), None);
        assert_eq!(ChildMode::parse(OsStr::new("stall-before-unknown")), None);
        assert_eq!(ChildMode::parse(OsStr::new("exit-after-unknown")), None);
    }

    #[test]
    fn fault_exit_codes_are_nonzero_and_unique() {
        let codes = FaultPoint::ALL
            .into_iter()
            .map(FaultPoint::exit_code)
            .collect::<BTreeSet<_>>();
        assert_eq!(codes.len(), FaultPoint::ALL.len());
        assert!(codes.iter().all(|code| *code > 0 && *code <= 255));
    }
}
