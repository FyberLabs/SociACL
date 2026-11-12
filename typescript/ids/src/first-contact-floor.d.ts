export type DescriptorFloor = Readonly<{revision:number;digest:string}>;
export interface FirstContactFloor {
  readonly owner:string;
  read():Promise<DescriptorFloor>;
  observe(candidate:DescriptorFloor,verify:(now:number)=>void):Promise<DescriptorFloor>;
  close():void;
}
export function openFirstContactFloor(options:{name:string;owner:string;anchor:DescriptorFloor;
  now:()=>number;create?:boolean;indexedDB?:IDBFactory}):Promise<FirstContactFloor>;
