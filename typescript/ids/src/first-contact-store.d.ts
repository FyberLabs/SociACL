export type Descriptor = { channelId:string; revision:number; encryptionEpub:string;
  expiresAt:number; maxLifetimeSeconds:number; maxMessageBytes:number };
export type Reservation = { replayKey:string; requestId:string; replayUntil:number;
  expiresAt:number; envelope:Uint8Array };
export type Grant = { ciphertextHex:string; rotationSeq:number };
export type Row = Reservation & { revision:number; status:'pending'|'accepted'|'rejected'|'delivered'; grant?:Grant };
export type Decision = {status:'rejected'} | ({status:'accepted'} & Grant);
export interface FirstContactStore {
  readonly owner:string;
  activate(policy:Omit<Descriptor,'channelId'|'revision'>):Promise<Descriptor>;
  disable():Promise<void>;
  descriptor():Promise<Descriptor>;
  reserve(descriptor:Descriptor,record:Reservation):Promise<boolean>;
  pending():Promise<Row[]>;
  decide(descriptor:Descriptor,replayKey:string,requestId:string,decision:Decision):Promise<void>;
  outbox():Promise<Row[]>;
  acknowledge(replayKey:string,requestId:string,ciphertextHex:string):Promise<void>;
  close():void;
}
export function openFirstContactStore(options:{name:string;owner:string;now:()=>number;
  create?:boolean;indexedDB?:IDBFactory}):Promise<FirstContactStore>;
