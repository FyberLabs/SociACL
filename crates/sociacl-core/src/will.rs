//! Will templates and the small named macro language.
//!
//! A will is written while the owner is alive and jointly stated, the same
//! way an edge is. It is not a Check query. Macros name a verb, a circle,
//! a threshold, a clock, and what to destroy. Parse and validate fail closed
//! on unnamed verbs, missing enrollment, dead-hand shapes, and mixed clocks.
//!
//! `highest-still-attesting-rank` and `named-successor-list` are named
//! templates. `military-rank` and `corporate-succession` are aliases for
//! those templates, not doctrine tables.

use std::collections::BTreeSet;

use crate::error::WillError;
use crate::types::{Clock, NodeId, Timestamp};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WillSubject {
    Object(NodeId),
    Group(NodeId),
    Network(NodeId),
    DeviceClass(NodeId),
}

impl WillSubject {
    pub fn id(&self) -> &NodeId {
        match self {
            Self::Object(id) | Self::Group(id) | Self::Network(id) | Self::DeviceClass(id) => id,
        }
    }

    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::Object(_) => "object",
            Self::Group(_) => "group",
            Self::Network(_) => "network",
            Self::DeviceClass(_) => "device-class",
        }
    }

    fn parse(kind: &str, id: impl Into<NodeId>) -> Result<Self, WillError> {
        let id = id.into();
        match kind {
            "object" => Ok(Self::Object(id)),
            "group" => Ok(Self::Group(id)),
            "network" => Ok(Self::Network(id)),
            "device-class" => Ok(Self::DeviceClass(id)),
            other => Err(WillError::Parse(format!("unknown subject kind {other}"))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestroyMaterial {
    Keys,
    Content,
}

impl DestroyMaterial {
    fn parse(s: &str) -> Result<Self, WillError> {
        match s {
            "keys" => Ok(Self::Keys),
            "content" => Ok(Self::Content),
            other => Err(WillError::Parse(format!(
                "unknown destroy material {other}"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Keys => "keys",
            Self::Content => "content",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WillClause {
    KeepOperating {
        circle: NodeId,
    },
    Remint {
        issuers: Vec<NodeId>,
    },
    Discover {
        heir: NodeId,
    },
    Elect {
        circle: NodeId,
        clock: Clock,
        threshold: u32,
        notify: Vec<NodeId>,
        wait: bool,
        cancel: bool,
    },
    Destroy {
        if_no_heir: bool,
        material: DestroyMaterial,
    },
    /// Named template: highest still-attesting member of this named circle.
    HighestStillAttestingRank {
        circle: NodeId,
    },
    /// Named template: this pre-written successor list.
    NamedSuccessorList {
        successors: Vec<NodeId>,
    },
}

impl WillClause {
    pub fn clock(&self) -> Option<Clock> {
        match self {
            Self::KeepOperating { .. } | Self::Remint { .. } => Some(Clock::KeepOperating),
            Self::Elect { clock, .. } => Some(*clock),
            Self::HighestStillAttestingRank { .. } | Self::NamedSuccessorList { .. } => {
                Some(Clock::Elect)
            }
            Self::Discover { .. } | Self::Destroy { .. } => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::KeepOperating { .. } => "keep-operating",
            Self::Remint { .. } => "remint",
            Self::Discover { .. } => "discover",
            Self::Elect { .. } => "elect",
            Self::Destroy { .. } => "destroy",
            Self::HighestStillAttestingRank { .. } => "highest-still-attesting-rank",
            Self::NamedSuccessorList { .. } => "named-successor-list",
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct WillBody {
    pub clauses: Vec<WillClause>,
}

impl WillBody {
    pub fn has_elect_path(&self) -> bool {
        self.clauses.iter().any(|c| {
            matches!(
                c,
                WillClause::Discover { .. }
                    | WillClause::Elect { .. }
                    | WillClause::HighestStillAttestingRank { .. }
                    | WillClause::NamedSuccessorList { .. }
            )
        })
    }

    pub fn has_destroy(&self) -> bool {
        self.clauses
            .iter()
            .any(|c| matches!(c, WillClause::Destroy { .. }))
    }

    pub fn named_heir(&self) -> Option<&NodeId> {
        self.clauses.iter().find_map(|c| match c {
            WillClause::Discover { heir } => Some(heir),
            _ => None,
        })
    }

    pub fn remint_issuers(&self) -> Option<&[NodeId]> {
        self.clauses.iter().find_map(|c| match c {
            WillClause::Remint { issuers } => Some(issuers.as_slice()),
            _ => None,
        })
    }

    pub fn elect(&self) -> Option<&WillClause> {
        self.clauses
            .iter()
            .find(|c| matches!(c, WillClause::Elect { .. }))
    }

    pub fn rank_circle(&self) -> Option<&NodeId> {
        self.clauses.iter().find_map(|c| match c {
            WillClause::HighestStillAttestingRank { circle } => Some(circle),
            WillClause::Elect { circle, .. } => Some(circle),
            _ => None,
        })
    }

    pub fn successor_list(&self) -> Option<&[NodeId]> {
        self.clauses.iter().find_map(|c| match c {
            WillClause::NamedSuccessorList { successors } => Some(successors.as_slice()),
            _ => None,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WillDisposition {
    Heir(NodeId),
    StaySecret,
}

/// Named template bound to an object, group, network, or device class.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Will {
    pub name: String,
    pub subject: WillSubject,
    pub testator: NodeId,
    pub body: WillBody,
    pub written_at: Timestamp,
    /// Instant the owner jointly stated this will (owner speaks for both sides).
    pub joint_at: Timestamp,
    pub cancelable_by: Vec<NodeId>,
    pub canceled: bool,
}

impl Will {
    pub fn object(&self) -> &NodeId {
        self.subject.id()
    }

    pub fn heir(
        object: impl Into<NodeId>,
        testator: impl Into<NodeId>,
        heir: impl Into<NodeId>,
        written_at: Timestamp,
        cancelable_by: Vec<NodeId>,
    ) -> Self {
        let object = object.into();
        Self {
            name: "heir".into(),
            subject: WillSubject::Object(object),
            testator: testator.into(),
            body: WillBody {
                clauses: vec![WillClause::Discover { heir: heir.into() }],
            },
            written_at,
            joint_at: written_at,
            cancelable_by,
            canceled: false,
        }
    }

    pub fn stay_secret(
        object: impl Into<NodeId>,
        testator: impl Into<NodeId>,
        written_at: Timestamp,
    ) -> Self {
        let object = object.into();
        Self {
            name: "stay-secret".into(),
            subject: WillSubject::Object(object),
            testator: testator.into(),
            body: WillBody {
                clauses: vec![WillClause::Destroy {
                    if_no_heir: true,
                    material: DestroyMaterial::Keys,
                }],
            },
            written_at,
            joint_at: written_at,
            cancelable_by: Vec::new(),
            canceled: false,
        }
    }

    pub fn disposition(&self) -> Option<WillDisposition> {
        if let Some(heir) = self.body.named_heir() {
            return Some(WillDisposition::Heir(heir.clone()));
        }
        if self.body.has_destroy() && !self.body.has_elect_path() {
            return Some(WillDisposition::StaySecret);
        }
        None
    }

    pub fn parse(src: &str) -> Result<Self, WillError> {
        parse_will(src)
    }

    pub fn validate(&self, ctx: &WillValidateCtx) -> Result<(), WillError> {
        if self.body.clauses.is_empty() {
            return Err(WillError::Empty);
        }
        for clause in &self.body.clauses {
            match clause {
                WillClause::KeepOperating { circle } => {
                    require_node(ctx, circle)?;
                }
                WillClause::Remint { issuers } => {
                    if issuers.is_empty() {
                        return Err(WillError::Parse("remint needs issuers".into()));
                    }
                    for issuer in issuers {
                        if !ctx.enrolled.contains(issuer) {
                            return Err(WillError::MissingEnrollment(issuer.clone()));
                        }
                    }
                }
                WillClause::Discover { heir } => {
                    require_node(ctx, heir)?;
                }
                WillClause::Elect {
                    circle,
                    clock,
                    cancel,
                    notify,
                    ..
                } => {
                    if *clock != Clock::Elect {
                        return Err(WillError::ClockMix("elect must use the Elect clock".into()));
                    }
                    if !*cancel {
                        return Err(WillError::ElectRequiresCancel);
                    }
                    require_node(ctx, circle)?;
                    for n in notify {
                        require_node(ctx, n)?;
                    }
                }
                WillClause::Destroy { .. } => {}
                WillClause::HighestStillAttestingRank { circle } => {
                    require_node(ctx, circle)?;
                }
                WillClause::NamedSuccessorList { successors } => {
                    if successors.is_empty() {
                        return Err(WillError::Parse("named-successor-list is empty".into()));
                    }
                    for s in successors {
                        require_node(ctx, s)?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn require_node(ctx: &WillValidateCtx, id: &NodeId) -> Result<(), WillError> {
    if ctx.nodes.contains(id) {
        Ok(())
    } else {
        Err(WillError::NodeNotFound(id.clone()))
    }
}

/// Nodes and enrollments known at write time.
#[derive(Clone, Debug, Default)]
pub struct WillValidateCtx {
    pub nodes: BTreeSet<NodeId>,
    pub enrolled: BTreeSet<NodeId>,
}

const DEAD_HAND: &[&str] = &[
    "if-silent-for",
    "if-inactive",
    "on-silence",
    "dead-hand",
    "silent-for",
    "inactivity",
    "elect-on-silence",
];

fn reject_forbidden(tokens: &[&str]) -> Result<(), WillError> {
    for t in tokens {
        if DEAD_HAND.contains(t) {
            return Err(WillError::DeadHand((*t).to_string()));
        }
        if *t == "heir-template" {
            return Err(WillError::HeirTemplate);
        }
        if *t == "vacancy" || *t == "vacancy-ad" {
            return Err(WillError::VacancyAd);
        }
        if *t == "timeout" {
            return Err(WillError::ClockMix(
                "one timeout cannot serve keep-operating and Elect".into(),
            ));
        }
    }
    Ok(())
}

fn parse_will(src: &str) -> Result<Will, WillError> {
    let mut name: Option<String> = None;
    let mut subject: Option<WillSubject> = None;
    let mut testator: Option<NodeId> = None;
    let mut cancelable_by: Vec<NodeId> = Vec::new();
    let mut clauses: Vec<WillClause> = Vec::new();

    for raw in src.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        reject_forbidden(&tokens)?;
        match tokens[0] {
            "will" => {
                // will <name> for <kind> <id>
                if tokens.len() != 5 || tokens[2] != "for" {
                    return Err(WillError::Parse(
                        "will <name> for <object|group|network|device-class> <id>".into(),
                    ));
                }
                name = Some(tokens[1].to_string());
                subject = Some(WillSubject::parse(tokens[3], tokens[4])?);
            }
            "written-by" => {
                if tokens.len() != 2 {
                    return Err(WillError::Parse("written-by <testator>".into()));
                }
                testator = Some(NodeId::new(tokens[1]));
            }
            "cancelable-by" => {
                cancelable_by = tokens[1..].iter().map(|s| NodeId::new(*s)).collect();
            }
            "keep-operating" => clauses.push(parse_keep_operating(&tokens)?),
            "remint" => clauses.push(parse_remint(&tokens)?),
            "discover" => clauses.push(parse_discover(&tokens)?),
            "elect" => clauses.push(parse_elect(&tokens)?),
            "destroy" => clauses.push(parse_destroy(&tokens)?),
            "highest-still-attesting-rank" | "military-rank" => {
                clauses.push(parse_rank(&tokens)?);
            }
            "named-successor-list" | "corporate-succession" => {
                clauses.push(parse_successors(&tokens)?);
            }
            other => return Err(WillError::UnnamedVerb(other.to_string())),
        }
    }

    let name = name.ok_or_else(|| WillError::Parse("missing will header".into()))?;
    let subject = subject.ok_or_else(|| WillError::Parse("missing will header".into()))?;
    let testator = testator.ok_or_else(|| WillError::Parse("missing written-by".into()))?;
    if clauses.is_empty() {
        return Err(WillError::Empty);
    }

    Ok(Will {
        name,
        subject,
        testator,
        body: WillBody { clauses },
        written_at: Timestamp(0),
        joint_at: Timestamp(0),
        cancelable_by,
        canceled: false,
    })
}

fn parse_clock_token(tokens: &[&str], implicit: Clock) -> Result<Clock, WillError> {
    let mut found = None;
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i] == "clock" {
            let Some(name) = tokens.get(i + 1) else {
                return Err(WillError::Parse("clock needs a name".into()));
            };
            let clock = match *name {
                "elect" => Clock::Elect,
                "keep-operating" => Clock::KeepOperating,
                other => {
                    return Err(WillError::ClockMix(format!("unnamed clock {other}")));
                }
            };
            found = Some(clock);
            i += 2;
            continue;
        }
        i += 1;
    }
    Ok(found.unwrap_or(implicit))
}

fn parse_keep_operating(tokens: &[&str]) -> Result<WillClause, WillError> {
    let clock = parse_clock_token(tokens, Clock::KeepOperating)?;
    if clock != Clock::KeepOperating {
        return Err(WillError::ClockMix(
            "keep-operating cannot use the Elect clock".into(),
        ));
    }
    let circle = named_value(tokens, "circle")
        .ok_or_else(|| WillError::Parse("keep-operating circle <id>".into()))?;
    Ok(WillClause::KeepOperating {
        circle: NodeId::new(circle),
    })
}

fn parse_remint(tokens: &[&str]) -> Result<WillClause, WillError> {
    let clock = parse_clock_token(tokens, Clock::KeepOperating)?;
    if clock != Clock::KeepOperating {
        return Err(WillError::ClockMix(
            "remint cannot use the Elect clock".into(),
        ));
    }
    let issuers = rest_after(tokens, "issuers");
    if issuers.is_empty() {
        return Err(WillError::Parse("remint issuers <id>+".into()));
    }
    Ok(WillClause::Remint {
        issuers: issuers.into_iter().map(NodeId::new).collect(),
    })
}

fn parse_discover(tokens: &[&str]) -> Result<WillClause, WillError> {
    let heir =
        named_value(tokens, "heir").ok_or_else(|| WillError::Parse("discover heir <id>".into()))?;
    Ok(WillClause::Discover {
        heir: NodeId::new(heir),
    })
}

fn parse_elect(tokens: &[&str]) -> Result<WillClause, WillError> {
    if !tokens.iter().any(|t| *t == "clock") {
        return Err(WillError::ElectClockRequired);
    }
    let clock = parse_clock_token(tokens, Clock::Elect)?;
    if clock != Clock::Elect {
        return Err(WillError::ClockMix("elect must use the Elect clock".into()));
    }
    let circle = named_value(tokens, "circle")
        .ok_or_else(|| WillError::Parse("elect circle <id>".into()))?;
    let threshold = named_value(tokens, "threshold")
        .map(|s| {
            s.parse::<u32>()
                .map_err(|_| WillError::Parse("threshold must be a number".into()))
        })
        .transpose()?
        .unwrap_or(1);
    if threshold < 1 {
        return Err(WillError::Parse("threshold must be at least 1".into()));
    }
    let notify = rest_after_until_keywords(
        tokens,
        "notify",
        &["wait", "cancel", "clock", "circle", "threshold"],
    );
    let wait = tokens.contains(&"wait");
    let cancel = tokens.contains(&"cancel");
    if !cancel {
        return Err(WillError::ElectRequiresCancel);
    }
    if !wait {
        return Err(WillError::Parse(
            "elect needs wait on the Elect clock".into(),
        ));
    }
    Ok(WillClause::Elect {
        circle: NodeId::new(circle),
        clock,
        threshold,
        notify: notify.into_iter().map(NodeId::new).collect(),
        wait,
        cancel,
    })
}

fn parse_destroy(tokens: &[&str]) -> Result<WillClause, WillError> {
    if !tokens.iter().any(|t| *t == "if-no-heir") {
        return Err(WillError::Parse("destroy if-no-heir <keys|content>".into()));
    }
    let material = tokens
        .iter()
        .find(|t| **t == "keys" || **t == "content")
        .copied()
        .unwrap_or("keys");
    Ok(WillClause::Destroy {
        if_no_heir: true,
        material: DestroyMaterial::parse(material)?,
    })
}

fn parse_rank(tokens: &[&str]) -> Result<WillClause, WillError> {
    let circle = named_value(tokens, "circle")
        .ok_or_else(|| WillError::Parse("highest-still-attesting-rank circle <id>".into()))?;
    Ok(WillClause::HighestStillAttestingRank {
        circle: NodeId::new(circle),
    })
}

fn parse_successors(tokens: &[&str]) -> Result<WillClause, WillError> {
    if tokens.len() < 2 {
        return Err(WillError::Parse("named-successor-list <id>+".into()));
    }
    Ok(WillClause::NamedSuccessorList {
        successors: tokens[1..].iter().map(|s| NodeId::new(*s)).collect(),
    })
}

fn named_value<'a>(tokens: &'a [&'a str], key: &str) -> Option<&'a str> {
    tokens
        .windows(2)
        .find(|w| w[0] == key)
        .map(|w| w[1])
        .filter(|v| {
            !matches!(
                *v,
                "clock"
                    | "circle"
                    | "threshold"
                    | "notify"
                    | "wait"
                    | "cancel"
                    | "issuers"
                    | "heir"
                    | "if-no-heir"
            )
        })
}

fn rest_after<'a>(tokens: &'a [&'a str], key: &str) -> Vec<&'a str> {
    rest_after_until_keywords(tokens, key, &["clock", "circle", "threshold", "notify"])
}

fn rest_after_until_keywords<'a>(tokens: &'a [&'a str], key: &str, stop: &[&str]) -> Vec<&'a str> {
    let Some(pos) = tokens.iter().position(|t| *t == key) else {
        return Vec::new();
    };
    tokens[pos + 1..]
        .iter()
        .copied()
        .take_while(|t| !stop.contains(t))
        .collect()
}
