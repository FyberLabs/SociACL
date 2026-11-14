export type GroupWrapContext=Readonly<{epoch:number;group:string;revisionId:string}>;
export type GroupReaderWrap=GroupWrapContext & Readonly<{scope:'group-key';target:'reader-epub';targetId:string;wrappedKey:string}>;
