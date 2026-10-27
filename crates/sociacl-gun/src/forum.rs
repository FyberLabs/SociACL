//! Forum souls on the `s3rch` graph.
//!
//! Identity is the GunDB SEA pubkey ([`PrincipalId`]). A wallet and a
//! Panopticon OAuth subject are linked credentials. They are not this key.
//!
//! Chat is a tagged [`crate::GunFeedNode`] under `s3rch/items`. These
//! builders do not create a chat tree. Anyone with Check see on a need
//! may post an offer. The need's owner or subject accepts one live
//! offer. Only the owner reopens. A ham update is accepted only when
//! Check see allows the writer. Accepting an offer does not elect an
//! owner. A hop, a status node, a chat tag, and a hint do not mint.

use std::collections::BTreeSet;

use sociacl_ids::{object_principal, parse_object_id, parse_principal_id, ObjectId, PrincipalId};

use crate::mesh::MeshSeeGraph;
use crate::soul::{GunSoul, S3RCH_FORUMS, S3RCH_ROOT};
use crate::GunError;

const ROLE_TOKEN_MAX: usize = 32;
const RESERVED_ROLE_TOKENS: &[&str] = &[
    "acl", "agents", "alarm", "chat", "forums", "items", "meta", "needs", "offers", "roles",
    "s3rch", "subtasks", "template", "updates", "users",
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
/// `body`, `severity`, and `spec` stay as posted. `accepted_offer` is
/// set only when `stated` is 0. Anyone with Check see may post an offer.
/// The owner or `subject` accepts one live offer. Only the owner
/// reopens. [`accept_need_transition`] does not admit an owner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForumNeed {
    pub id: ObjectId,
    pub forum_id: ObjectId,
    pub subject: PrincipalId,
    pub severity: ForumNeedSeverity,
    pub body: String,
    /// `1` open. `0` resolved. Any other value is invalid.
    pub stated: u8,
    pub ham_state: u64,
    pub ts: u64,
    /// Offer accepted by the owner or `subject`. Present only when
    /// `stated` is 0. Cleared when the owner reopens.
    pub accepted_offer: Option<ObjectId>,
    /// Object id of a function contract. Absent on a free-form need.
    pub spec: Option<ObjectId>,
}

impl ForumNeed {
    pub fn validate(&self) -> Result<(), GunError> {
        if self.stated > 1 {
            return Err(GunError::ForumSoul);
        }
        match (&self.accepted_offer, self.stated) {
            (Some(offer), 0) => require_kind(offer, "offer")?,
            (None, 1) => {}
            _ => return Err(GunError::ForumSoul),
        }
        if let Some(spec) = &self.spec {
            require_minted(spec)?;
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

/// Offer under a need. The helper owns it.
///
/// Soul: `s3rch/forums/<forumId>/needs/<needId>/offers/<offerId>`.
/// `stated` 1 is live. `stated` 0 is withdrawn or cancelled.
/// `artifacts` is a comma-separated list of object ids. It is not key
/// material. The offer does not spend tokens and it does not elect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ForumOffer {
    pub id: ObjectId,
    pub need: ObjectId,
    pub forum_id: ObjectId,
    pub helper: PrincipalId,
    pub body: String,
    pub artifacts: String,
    pub stated: u8,
}

impl ForumOffer {
    pub fn validate(&self) -> Result<(), GunError> {
        if self.stated > 1 {
            return Err(GunError::ForumSoul);
        }
        require_kind(&self.id, "offer")?;
        let embedded = object_principal(&self.id).map_err(|_| GunError::ForumSoul)?;
        if embedded != self.helper {
            return Err(GunError::ForumSoul);
        }
        require_kind(&self.need, "need")?;
        require_kind(&self.forum_id, "forum")?;
        csv_object_ids(&self.artifacts, None)?;
        forum_offer_soul(&self.forum_id, &self.need, &self.id).map(|_| ())
    }

    pub fn soul(&self) -> Result<GunSoul, GunError> {
        self.validate()?;
        forum_offer_soul(&self.forum_id, &self.need, &self.id)
    }
}

/// Post or withdraw an offer.
///
/// `current` absent and `next.stated` 1 posts. The writer is the helper
/// and must pass Check see on the open need. A missing admission does
/// not post. `current` live and `next.stated` 0 withdraws. The helper
/// may withdraw their own offer. The need's owner or subject may cancel
/// it. That cancel does not resolve the need and it does not delete the
/// offer. A cancelled offer is not posted again. This does not admit an
/// owner and it does not read a hint or a hop.
pub fn accept_offer_transition(
    graph: &MeshSeeGraph,
    need: &ForumNeed,
    current: Option<&ForumOffer>,
    next: &ForumOffer,
    writer: &PrincipalId,
    now: u64,
) -> Result<ForumOffer, GunError> {
    need.validate()?;
    next.validate()?;
    if next.need != need.id || next.forum_id != need.forum_id {
        return Err(GunError::ForumSoul);
    }
    match current {
        None => {
            if next.stated != 1 || need.stated != 1 || writer != &next.helper {
                return Err(GunError::ForumSoul);
            }
            let seen = graph.check_see(&need.id, writer, now, None, None);
            if !seen.allowed {
                return Err(if seen.reason == "unknown" {
                    GunError::ObjectNotInGraph
                } else {
                    GunError::ForumSoul
                });
            }
            Ok(next.clone())
        }
        Some(current) => {
            current.validate()?;
            if current.id != next.id
                || current.need != next.need
                || current.forum_id != next.forum_id
                || current.helper != next.helper
                || current.body != next.body
                || current.artifacts != next.artifacts
                || current.stated != 1
                || next.stated != 0
            {
                return Err(GunError::ForumSoul);
            }
            if writer == &current.helper {
                return Ok(next.clone());
            }
            let owner = admitted_owner(graph, &need.id)?;
            if writer == owner || writer == &need.subject {
                Ok(next.clone())
            } else {
                Err(GunError::ForumSoul)
            }
        }
    }
}

/// Accept `next` as the stored need.
///
/// `id`, `forum_id`, `subject`, `body`, `severity`, and `spec` stay.
/// `next.ham_state` must be strictly greater. A missing admission does
/// not. Stated 1 to 0 accepts `offer`: the writer is the admitted owner
/// or `subject`, `accepted_offer` names that live offer, and the need
/// resolves. Stated 0 to 1 reopens: the writer is the admitted owner,
/// and `accepted_offer` is cleared. Offers already posted stay. A ham
/// update that keeps `stated` and `accepted_offer` is a Check see write.
/// This does not admit an owner and it does not read a hint or a hop.
pub fn accept_need_transition(
    graph: &MeshSeeGraph,
    current: &ForumNeed,
    next: &ForumNeed,
    offer: Option<&ForumOffer>,
    writer: &PrincipalId,
    now: u64,
) -> Result<ForumNeed, GunError> {
    current.validate()?;
    next.validate()?;
    if next.id != current.id
        || next.forum_id != current.forum_id
        || next.subject != current.subject
        || next.body != current.body
        || next.severity != current.severity
        || next.spec != current.spec
    {
        return Err(GunError::ForumSoul);
    }
    if next.ham_state <= current.ham_state {
        return Err(GunError::ForumSoul);
    }
    let owner = admitted_owner(graph, &current.id)?;
    let resolving = current.stated == 1 && next.stated == 0;
    let reopening = current.stated == 0 && next.stated == 1;
    if resolving {
        let Some(offer) = offer else {
            return Err(GunError::ForumSoul);
        };
        offer.validate()?;
        if offer.stated != 1
            || offer.need != current.id
            || offer.forum_id != current.forum_id
            || next.accepted_offer.as_ref() != Some(&offer.id)
        {
            return Err(GunError::ForumSoul);
        }
        if writer != owner && writer != &current.subject {
            return Err(GunError::ForumSoul);
        }
        return Ok(next.clone());
    }
    if reopening {
        if offer.is_some() || next.accepted_offer.is_some() || writer != owner {
            return Err(GunError::ForumSoul);
        }
        return Ok(next.clone());
    }
    if current.stated == next.stated && current.accepted_offer == next.accepted_offer {
        if offer.is_some() {
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
        return Ok(next.clone());
    }
    Err(GunError::ForumSoul)
}

fn admitted_owner<'a>(
    graph: &'a MeshSeeGraph,
    object: &ObjectId,
) -> Result<&'a PrincipalId, GunError> {
    match graph.admitted_owner(object) {
        Some((owner, _)) => Ok(owner),
        None => Err(GunError::ObjectNotInGraph),
    }
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

/// `s3rch/forums/<forumId>/needs/<needId>/offers/<offerId>`.
pub fn forum_offer_soul(
    forum: &ObjectId,
    need: &ObjectId,
    offer: &ObjectId,
) -> Result<GunSoul, GunError> {
    require_kind(forum, "forum")?;
    require_kind(need, "need")?;
    require_kind(offer, "offer")?;
    Ok(soul([
        S3RCH_ROOT,
        S3RCH_FORUMS,
        forum.as_ref(),
        "needs",
        need.as_ref(),
        "offers",
        offer.as_ref(),
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

    /// Parsed offer soul: forum, need, offer.
    pub fn as_forum_offer(&self) -> Option<(ObjectId, ObjectId, ObjectId)> {
        let segments = self.segments();
        if segments.len() != 7
            || segments[0] != S3RCH_ROOT
            || segments[1] != S3RCH_FORUMS
            || segments[3] != "needs"
            || segments[5] != "offers"
        {
            return None;
        }
        let forum = parse_object_id(&segments[2]).ok()?;
        let need = parse_object_id(&segments[4]).ok()?;
        let offer = parse_object_id(&segments[6]).ok()?;
        if object_kind(&forum) != Some("forum")
            || object_kind(&need) != Some("need")
            || object_kind(&offer) != Some("offer")
        {
            return None;
        }
        Some((forum, need, offer))
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
    require_minted(id)
}

fn require_minted(id: &ObjectId) -> Result<(), GunError> {
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
