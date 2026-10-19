/**
 * Test-only label plant. The package exports do not name this file.
 * Production owner reads the admitted signed record. This plant does not.
 */
import { parseObjectId } from '../../ids/src/index.js';
import { labelObjects } from './label-objects.js';

/**
 * Plant a label owner without the signed-owner guard.
 * The key is the parsed object id.
 * @param {object} graph
 * @param {string} object
 * @param {string} owner
 */
export function plantLabelOwnerForTest(graph, object, owner) {
  const id = parseObjectId(object);
  if (!id.ok || typeof owner !== 'string') return;
  labelObjects(graph).set(id.value, { id: id.value, owner });
}
