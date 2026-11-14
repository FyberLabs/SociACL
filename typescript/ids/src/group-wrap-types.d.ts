export type GroupItemContext=Readonly<{epoch:number;object:string;group:string;revisionId:string}>;
export type GroupItemWrap=GroupItemContext & Readonly<{scope:'item-dek';target:'group-epoch';targetId:string;wrappedKey:string}>;
