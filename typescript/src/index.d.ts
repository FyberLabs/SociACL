export const HOPCAP: 1;
export const DEFAULT_PRIVILEGE_UP_DELAY: number;
export const DEFAULT_ELECT_WAIT: number;
export const RELATIONS: readonly string[];
export const PREDICATES: readonly string[];
export const CENSURE_REASONS: readonly string[];

export class SociaclError extends Error {}

export type CheckResult = { allowed: boolean; reason: string };

export class Plane {
  now(): number;
  setNow(tick: number): void;
  addPerson(id: string): void;
  addAgent(id: string): void;
  addDevice(id: string): void;
  addGroup(id: string): void;
  addCircle(id: string): void;
  addNetwork(id: string): void;
  addObject(id: string, owner: string): void;
  setObjectProperty(object: string, key: string, value: string): void;
  setAuthn(id: string, state: "live" | "gone"): void;
  authnOf(id: string): "live" | "gone";
  stateEdge(speaker: string, from: string, to: string, relation: string): void;
  jointlyState(from: string, to: string, relation: string): void;
  unstateEdge(speaker: string, from: string, to: string, relation: string): void;
  delegate(
    owner: string,
    principal: string,
    object: string,
    actions: string,
    until?: number | null,
  ): void;
  jointlyDelegate(
    owner: string,
    principal: string,
    object: string,
    actions: string,
    until?: number | null,
  ): void;
  undelegate(owner: string, principal: string, object: string): void;
  admitMember(member: string, network: string): void;
  censure(speaker: string, network: string, member: string, reason: string): string;
  isMember(member: string, network: string): boolean;
  audit(network: string): string[];
  writeWill(src: string): void;
  check(
    action: string,
    object: string,
    accessor: string,
    predicate?: string,
  ): CheckResult;
  remint(object: string, principal: string): "remint";
  discover(object: string): string;
  elect(object: string): string;
  commitElect(object: string): string;
  cancelWill(object: string, by: string): string;
  destroy(object: string): "destroy";
}
