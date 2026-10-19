import { checkPost } from "./src/post.js";
import { checkSee } from "./src/see.js";

declare const g: {
  hasObject(object: import("./ids/src/types.js").ObjectId): boolean;
  ownerOf(object: import("./ids/src/types.js").ObjectId): import("./ids/src/types.js").PrincipalId | undefined;
};

// @ts-expect-error checkSee(g, "room", "0xbob", 0)
checkSee(g, "room", "0xbob", 0);

// @ts-expect-error checkPost(g, "room", "0xbob", 0)
checkPost(g, "room", "0xbob", 0);
