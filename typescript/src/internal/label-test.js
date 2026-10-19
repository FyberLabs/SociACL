/**
 * Test-only label plant. The package exports do not name this file.
 * Production puts go through MemoryGroupGraph.putObject.
 */
import { aclKey } from '../group.js';
import { objectIdRejected } from '../legacy/gun-legacy.js';
import { labelObjects } from './label-objects.js';

/**
 * Plant a label owner without the signed-owner guard.
 * @param {object} graph
 * @param {string} object
 * @param {string} owner
 */
export function plantLabelOwnerForTest(graph, object, owner) {
  const text = String(object ?? '');
  if (objectIdRejected(text) || typeof owner !== 'string') return;
  labelObjects(graph).set(aclKey(text), { id: text, owner });
}
