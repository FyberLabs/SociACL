//! Forum souls on the `s3rch` graph.
//!
//! Identity is the GunDB SEA pubkey ([`PrincipalId`]). A wallet and a
//! Panopticon OAuth subject are linked credentials. They are not this key.
//!
//! Chat is a tagged [`crate::GunFeedNode`] under `s3rch/items`. These
//! builders do not create a chat tree. A stated or ham update on a need
//! is accepted only when Check see allows the writer on that need.
//! It does not elect an owner.

use std::collections::BTreeSet;

use sociacl_ids::{object_principal, parse_object_id, parse_principal_id, ObjectId, PrincipalId};

use crate::mesh::MeshSeeGraph;
use crate::soul::{GunSoul, S3RCH_FORUMS, S3RCH_ROOT};
use crate::GunError;

const ROLE_TOKEN_MAX: usize = 32;
const RESERVED_ROLE_TOKENS: &[&str] = &[
    "acl", "agents", "alarm", "chat", "forums", "items", "meta", "needs", "roles", "s3rch",
    "subtasks", "template", "updates", "users",
];

/// How a forum template assigns role windows.
///
/// `distinct-principals`: each role token names a different SEA principal.
/// `role-labels`: one SEA principal wears several role tokens.
/// A role token is not a Check predicate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ForumRoleMode {
    DistinctPrincipals,
    RoleLabels,
}

impl ForumRoleMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DistinctPrincipals => "distinct-principals",
            Self::RoleLabels => "role-labels",
        }
    }

    /// Exact spelling. Nothing is trimmed.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "distinct-principals" => Some(Self::DistinctPrincipals),
            "role-labels" => Some(Self::RoleLabels),
            _ => None,
        }
    }
}

/// Status dot on one agent tile. Data on the status node. Not a grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ForumAgentState {
    Idle,
    Working,
    Needs,
    Emergency,
}

impl ForumAgentState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Working => "working",
            Self::Needs => "needs",
            Self::Emergency => "emergency",
        }
    }

    /// Exact spelling. Nothing is trimmed.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "idle" => Some(Self::Idle),
            "working" => Some(Self::Working),
            "needs" => Some(Self::Needs),
            "emergency" => Some(Self::Emergency),
            _ => None,
        }
    }
}

/// Severity stored on a need object. Not a grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ForumNeedSeverity {
    Need,
    Emergency,
}

impl ForumNeedSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Need => "need",
            Self::Emergency => "emergency",
        }
    }

    /// Exact spelling. Nothing is trimmed.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "need" => Some(Self::Need),
            "emergency" => Some(Self::Emergency),
            _ => None,
        }
    }
}

/// One role token worn by one SEA principal. The token is not a principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForumRoleMembership {
    pub role: String,
    pub principal: PrincipalId,
}

/// Template choice for a forum. Not a Check object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForumTemplate {
    pub forum_id: ObjectId,
    pub mode: ForumRoleMode,
}

impl ForumTemplate {
    pub fn validate(&self) -> Result<(), GunError> {
        require_kind(&self.forum_id, "forum")?;
        forum_template_soul(&self.forum_id).map(|_| ())
    }

    pub fn soul(&self) -> Result<GunSoul, GunError> {
        self.validate()?;
        forum_template_soul(&self.forum_id)
    }
}

/// Per-agent status node.
///
/// Soul: `s3rch/forums/<forumId>/agents/<seaPubkey>`.
/// `started`, `tokens`, and `runtime` are this agent's counters.
/// `tokens` is not a transfer. Optional `hb`, `batt`, and `link` are vitals.
/// `needs` and `artifacts` are comma-separated object ids. Gun has no arrays.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForumAgentStatus {
    pub id: ObjectId,
    pub forum_id: ObjectId,
    pub agent: PrincipalId,
    pub task: String,
    pub result: String,
    pub needs: String,
    pub progress: u64,
    pub state: ForumAgentState,
    pub last_prompt: String,
    pub last_update: u64,
    pub agent_type: String,
    pub started: u64,
    pub tokens: u64,
    pub runtime: u64,
    pub hb: Option<u64>,
    pub batt: Option<u64>,
    pub link: Option<u64>,
    pub artifacts: String,
}

impl ForumAgentStatus {
    pub fn validate(&self) -> Result<(), GunError> {
        require_kind(&self.id, "status")?;
        let embedded = object_principal(&self.id).map_err(|_| GunError::ForumSoul)?;
        if embedded != self.agent {
            return Err(GunError::ForumSoul);
        }
        require_kind(&self.forum_id, "forum")?;
        csv_object_ids(&self.needs, Some("need"))?;
        csv_object_ids(&self.artifacts, None)?;
        forum_agent_soul(&self.forum_id, &self.agent).map(|_| ())
    }

    pub fn soul(&self) -> Result<GunSoul, GunError> {
        self.validate()?;
        forum_agent_soul(&self.forum_id, &self.agent)
    }
}

/// Need object. `stated` 1 is open. `stated` 0 is resolved.
///
/// `subject` is the SEA pubkey the need is about. [`ForumNeed::validate`]
/// does not compare it to `forum_id` or to the principal embedded in
/// that id.
///
/// Anyone with Check see on this need may resolve it. The stated or
/// `ham_state` update is accepted only by [`accept_need_transition`].
/// A missing admission does not accept the update. The admitted owner
/// stays the owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForumNeed {
    pub id: ObjectId,
    pub forum_id: ObjectId,
    pub subject: PrincipalId,
    pub severity: ForumNeedSeverity,
    pub body: String,
    pub stated: u8,
    pub ham_state: u64,
    pub ts: u64,
}

impl ForumNeed {
    pub fn validate(&self) -> Result<(), GunError> {
        if self.stated > 1 {
            return Err(GunError::ForumSoul);
        }
        require_kind(&self.id, "need")?;
        require_kind(&self.forum_id, "forum")?;
        forum_need_soul(&self.forum_id, &self.id).map(|_| ())
    }

    pub fn soul(&self) -> Result<GunSoul, GunError> {
        self.validate()?;
        forum_need_soul(&self.forum_id, &self.id)
    }
}

/// Accept `next` as the stored need only when Check see allows `writer`
/// on `current.id`. Anyone that Check allows may resolve. A missing
/// admission does not. `next.ham_state` must be strictly greater.
/// `id`, `forum_id`, and `subject` stay. This does not admit an owner
/// and it does not read a hint or a hop.
pub fn accept_need_transition(
    graph: &MeshSeeGraph,
    current: &ForumNeed,
    next: &ForumNeed,
    writer: &PrincipalId,
    now: u64,
) -> Result<ForumNeed, GunError> {
    current.validate()?;
    next.validate()?;
    if next.id != current.id || next.forum_id != current.forum_id || next.subject != current.subject
    {
        return Err(GunError::ForumSoul);
    }
    if next.ham_state <= current.ham_state {
        return Err(GunError::ForumSoul);
    }
    let seen = graph.check_see(&current.id, writer, now, None, None);
    if !seen.allowed {
        return Err(if seen.reason == "unknown" {
            GunError::ObjectNotInGraph
        } else {
            GunError::ForumSoul
        });
    }
    Ok(next.clone())
}

/// Pinned emergency need for one forum.
///
/// Soul: `s3rch/forums/<forumId>/alarm`. `pinned` is 1.
/// The node is data. It is not a grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForumAlarm {
    pub forum_id: ObjectId,
    pub need: ObjectId,
    pub pinned: u8,
}

impl ForumAlarm {
    pub fn validate(&self) -> Result<(), GunError> {
        if self.pinned != 1 {
            return Err(GunError::ForumSoul);
        }
        require_kind(&self.forum_id, "forum")?;
        require_kind(&self.need, "need")?;
        forum_alarm_soul(&self.forum_id).map(|_| ())
    }

    pub fn soul(&self) -> Result<GunSoul, GunError> {
        self.validate()?;
        forum_alarm_soul(&self.forum_id)
    }

    /// The pin names this open emergency need in the same forum.
    ///
    /// An alarm or a need that fails [`ForumAlarm::validate`] or
    /// [`ForumNeed::validate`] does not pin.
    pub fn pins_open_emergency(&self, need: &ForumNeed) -> bool {
        if self.validate().is_err() || need.validate().is_err() {
            return false;
        }
        self.forum_id == need.forum_id
            && self.need == need.id
            && self.pinned == 1
            && need.severity == ForumNeedSeverity::Emergency
            && need.stated == 1
    }
}

/// Global emergency alarm.
///
/// True when any status tile is `emergency`, or when the pinned need
/// is an open emergency. Either input is enough. This is data for the
/// header alarm. It is not a Check and it is not a grant.
pub fn forum_emergency_alarm(
    states: &[ForumAgentState],
    alarm: Option<&ForumAlarm>,
    need: Option<&ForumNeed>,
) -> bool {
    let tiles = states
        .iter()
        .any(|state| *state == ForumAgentState::Emergency);
    let pin = match (alarm, need) {
        (Some(alarm), Some(need)) => alarm.pins_open_emergency(need),
        _ => false,
    };
    tiles || pin
}

/// `s3rch/forums/<forumId>/agents/<seaPubkey>`.
///
/// `seaPubkey` is the SEA [`PrincipalId`], not a `p_` key and not a wallet.
pub fn forum_agent_soul(forum: &ObjectId, agent: &PrincipalId) -> Result<GunSoul, GunError> {
    require_kind(forum, "forum")?;
    Ok(soul([
        S3RCH_ROOT,
        S3RCH_FORUMS,
        forum.as_ref(),
        "agents",
        agent.as_ref(),
    ]))
}

/// `s3rch/forums/<forumId>/needs/<needId>`.
pub fn forum_need_soul(forum: &ObjectId, need: &ObjectId) -> Result<GunSoul, GunError> {
    require_kind(forum, "forum")?;
    require_kind(need, "need")?;
    Ok(soul([
        S3RCH_ROOT,
        S3RCH_FORUMS,
        forum.as_ref(),
        "needs",
        need.as_ref(),
    ]))
}

/// `s3rch/forums/<forumId>/alarm`.
pub fn forum_alarm_soul(forum: &ObjectId) -> Result<GunSoul, GunError> {
    require_kind(forum, "forum")?;
    Ok(soul([S3RCH_ROOT, S3RCH_FORUMS, forum.as_ref(), "alarm"]))
}

/// `s3rch/forums/<forumId>/template`.
pub fn forum_template_soul(forum: &ObjectId) -> Result<GunSoul, GunError> {
    require_kind(forum, "forum")?;
    Ok(soul([S3RCH_ROOT, S3RCH_FORUMS, forum.as_ref(), "template"]))
}

/// `s3rch/forums/<forumId>/roles/<roleToken>/<seaPubkey>`.
///
/// The role token is lowercase ASCII, digits, and hyphen. It is not a
/// principal and not a Check predicate.
pub fn forum_role_soul(
    forum: &ObjectId,
    role: &str,
    principal: &PrincipalId,
) -> Result<GunSoul, GunError> {
    require_kind(forum, "forum")?;
    if !role_token_ok(role) {
        return Err(GunError::ForumSoul);
    }
    Ok(soul([
        S3RCH_ROOT,
        S3RCH_FORUMS,
        forum.as_ref(),
        "roles",
        role,
        principal.as_ref(),
    ]))
}

/// `s3rch/forums/<forumId>/agents/<seaPubkey>/subtasks/<objectId>`.
pub fn forum_subtask_soul(
    forum: &ObjectId,
    agent: &PrincipalId,
    subtask: &ObjectId,
) -> Result<GunSoul, GunError> {
    require_kind(forum, "forum")?;
    object_principal(subtask).map_err(|_| GunError::ForumSoul)?;
    Ok(soul([
        S3RCH_ROOT,
        S3RCH_FORUMS,
        forum.as_ref(),
        "agents",
        agent.as_ref(),
        "subtasks",
        subtask.as_ref(),
    ]))
}

/// `s3rch/forums/<forumId>/agents/<seaPubkey>/updates/<objectId>`.
pub fn forum_update_soul(
    forum: &ObjectId,
    agent: &PrincipalId,
    update: &ObjectId,
) -> Result<GunSoul, GunError> {
    require_kind(forum, "forum")?;
    object_principal(update).map_err(|_| GunError::ForumSoul)?;
    Ok(soul([
        S3RCH_ROOT,
        S3RCH_FORUMS,
        forum.as_ref(),
        "agents",
        agent.as_ref(),
        "updates",
        update.as_ref(),
    ]))
}

/// Tag carried on a [`crate::GunFeedNode`] under `s3rch/items`.
///
/// The spelling is `forum:<forumId>`. It is not a soul.
pub fn forum_chat_tag(forum: &ObjectId) -> Result<String, GunError> {
    require_kind(forum, "forum")?;
    Ok(format!("forum:{}", forum.as_ref()))
}

/// Comma-separated tags for a forum chat statement.
///
/// The forum tag is first. Extra tags stay as written: a tag that is
/// not already lowercase is rejected, and so is the tag `chat`.
/// A comma is rejected, so one extra cannot become two tags on read.
/// A repeated extra is kept once. Nothing here is lowercased.
pub fn forum_chat_tags(
    forum: &ObjectId,
    extra: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<String, GunError> {
    let tag = forum_chat_tag(forum)?;
    let mut seen = BTreeSet::new();
    let mut raw = Vec::new();
    seen.insert(tag.clone());
    raw.push(tag);
    for extra in extra {
        let extra = extra.as_ref();
        if !tag_token_ok(extra) {
            return Err(GunError::ForumSoul);
        }
        if seen.insert(extra.to_string()) {
            raw.push(extra.to_string());
        }
    }
    Ok(raw.join(","))
}

/// True when `tags` contains this forum's chat tag.
pub fn forum_chat_tag_present(tags: &str, forum: &ObjectId) -> bool {
    let Ok(tag) = forum_chat_tag(forum) else {
        return false;
    };
    crate::leaf::split_tags(tags)
        .iter()
        .any(|item| item == &tag)
}

/// True when `path` is a separate chat tree.
///
/// `s3rch/items/…` is false. `s3rch/chat` and any soul with a `chat`
/// segment are true. Forum chat does not use those paths.
pub fn is_separate_chat_soul(path: &str) -> bool {
    if path == "s3rch/chat" || path.starts_with("s3rch/chat/") {
        return true;
    }
    match GunSoul::parse(path) {
        Ok(soul) => soul.segments().iter().any(|segment| segment == "chat"),
        Err(_) => path.split('/').any(|segment| segment == "chat"),
    }
}

/// Both template modes. A role token is not a Check predicate.
///
/// Distinct principals: one principal per role token, and each principal
/// wears one token. Role labels: every token names the same principal.
/// An empty set matches either mode.
pub fn forum_roles_match(mode: ForumRoleMode, rows: &[ForumRoleMembership]) -> bool {
    if rows.iter().any(|row| !role_token_ok(&row.role)) {
        return false;
    }
    match mode {
        ForumRoleMode::DistinctPrincipals => {
            let mut roles = BTreeSet::new();
            let mut principals = BTreeSet::new();
            for row in rows {
                if !roles.insert(row.role.as_str()) {
                    return false;
                }
                if !principals.insert(row.principal.as_ref()) {
                    return false;
                }
            }
            true
        }
        ForumRoleMode::RoleLabels => {
            let mut roles = BTreeSet::new();
            let mut principal: Option<&str> = None;
            for row in rows {
                if !roles.insert(row.role.as_str()) {
                    return false;
                }
                match principal {
                    None => principal = Some(row.principal.as_ref()),
                    Some(current) if current != row.principal.as_ref() => return false,
                    Some(_) => {}
                }
            }
            true
        }
    }
}

impl GunSoul {
    /// Parsed agent status soul, when every segment matches.
    pub fn as_forum_agent(&self) -> Option<(ObjectId, PrincipalId)> {
        let segments = self.segments();
        if segments.len() != 5
            || segments[0] != S3RCH_ROOT
            || segments[1] != S3RCH_FORUMS
            || segments[3] != "agents"
        {
            return None;
        }
        let forum = parse_object_id(&segments[2]).ok()?;
        if object_kind(&forum) != Some("forum") {
            return None;
        }
        let agent = parse_principal_id(&segments[4]).ok()?;
        Some((forum, agent))
    }

    /// Parsed need soul.
    pub fn as_forum_need(&self) -> Option<(ObjectId, ObjectId)> {
        let segments = self.segments();
        if segments.len() != 5
            || segments[0] != S3RCH_ROOT
            || segments[1] != S3RCH_FORUMS
            || segments[3] != "needs"
        {
            return None;
        }
        let forum = parse_object_id(&segments[2]).ok()?;
        let need = parse_object_id(&segments[4]).ok()?;
        if object_kind(&forum) != Some("forum") || object_kind(&need) != Some("need") {
            return None;
        }
        Some((forum, need))
    }

    /// Forum id named by an alarm soul.
    pub fn as_forum_alarm(&self) -> Option<ObjectId> {
        let segments = self.segments();
        if segments.len() != 4
            || segments[0] != S3RCH_ROOT
            || segments[1] != S3RCH_FORUMS
            || segments[3] != "alarm"
        {
            return None;
        }
        let forum = parse_object_id(&segments[2]).ok()?;
        (object_kind(&forum) == Some("forum")).then_some(forum)
    }

    /// Forum id named by a template soul.
    pub fn as_forum_template(&self) -> Option<ObjectId> {
        let segments = self.segments();
        if segments.len() != 4
            || segments[0] != S3RCH_ROOT
            || segments[1] != S3RCH_FORUMS
            || segments[3] != "template"
        {
            return None;
        }
        let forum = parse_object_id(&segments[2]).ok()?;
        (object_kind(&forum) == Some("forum")).then_some(forum)
    }

    /// Parsed role membership soul.
    pub fn as_forum_role(&self) -> Option<(ObjectId, String, PrincipalId)> {
        let segments = self.segments();
        if segments.len() != 6
            || segments[0] != S3RCH_ROOT
            || segments[1] != S3RCH_FORUMS
            || segments[3] != "roles"
            || !role_token_ok(&segments[4])
        {
            return None;
        }
        let forum = parse_object_id(&segments[2]).ok()?;
        if object_kind(&forum) != Some("forum") {
            return None;
        }
        let principal = parse_principal_id(&segments[5]).ok()?;
        Some((forum, segments[4].clone(), principal))
    }
}

fn soul(segments: impl IntoIterator<Item = impl AsRef<str>>) -> GunSoul {
    GunSoul::new(segments)
}

fn object_kind(id: &ObjectId) -> Option<&str> {
    id.as_ref().split_once('_').map(|(kind, _)| kind)
}

fn require_kind(id: &ObjectId, kind: &str) -> Result<(), GunError> {
    if object_kind(id) != Some(kind) {
        return Err(GunError::ForumSoul);
    }
    object_principal(id)
        .map(|_| ())
        .map_err(|_| GunError::ForumSoul)
}

fn role_token_ok(token: &str) -> bool {
    let bytes = token.as_bytes();
    (1..=ROLE_TOKEN_MAX).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && !RESERVED_ROLE_TOKENS.contains(&token)
}

fn tag_token_ok(tag: &str) -> bool {
    !tag.is_empty()
        && tag != "chat"
        && tag == tag.to_ascii_lowercase()
        && !tag.contains('/')
        && !tag.contains(".get(")
        && !tag.contains([',', '#', '$', '[', ']', '~'])
        && tag.chars().all(|c| !c.is_control() && !c.is_whitespace())
}

fn csv_object_ids(value: &str, kind: Option<&str>) -> Result<Vec<ObjectId>, GunError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for part in value.split(',') {
        let id = parse_object_id(part).map_err(|_| GunError::ForumSoul)?;
        if let Some(kind) = kind {
            if object_kind(&id) != Some(kind) {
                return Err(GunError::ForumSoul);
            }
        }
        if !seen.insert(id.as_ref().to_string()) {
            return Err(GunError::ForumSoul);
        }
        out.push(id);
    }
    Ok(out)
}
