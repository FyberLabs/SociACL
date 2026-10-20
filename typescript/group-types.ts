import { checkGroupPresentation, checkGroupSee } from "./src/group.js";

declare const graph: object;

// @ts-expect-error checkGroupSee rejects a raw object string
checkGroupSee(graph, "same-group", "room", "0xbob", 0);

// @ts-expect-error checkGroupPresentation rejects a raw set string
checkGroupPresentation(graph, "set", "room", "0xbob", null, 0);
