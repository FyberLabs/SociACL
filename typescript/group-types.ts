import { checkGroupPresentation, checkGroupSee } from "./src/group.js";

declare const graph: object;

// @ts-expect-error checkGroupSee rejects a raw object string
checkGroupSee(graph, "same-group", "room", "0xbob", 0);

// @ts-expect-error checkGroupPresentation rejects a raw set string
checkGroupPresentation(graph, "set", "room", "0xbob", null, 0);

// Business metadata uses parsed ids; it cannot name role strings as principals.
import { forumMountSoul, forumRoleWindowSoul, type ForumRoleWindow, type ForumSharedMount } from "../docs/s3rch-check.js";
declare const window: ForumRoleWindow;
declare const mount: ForumSharedMount;
forumMountSoul(mount.forumId, mount.id);
forumRoleWindowSoul(window.forumId, window.role, window.id);
// @ts-expect-error a raw role token cannot be a mount target
const badMount: ForumSharedMount = { ...mount, target: "treasurer" };
// @ts-expect-error a UI mode cannot add execution authority
const badMode: ForumSharedMount = { ...mount, mode: "execute" };
// @ts-expect-error the role window id must be parsed
const badWindow: ForumRoleWindow = { ...window, id: "window" };
