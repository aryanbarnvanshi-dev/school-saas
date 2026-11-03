/**
 * School SaaS E2E Test Suite - Assertion Helpers
 * Provides descriptive error reporting and invariant checking for tests.
 */

const assert = require('assert');

function assertEqual(actual, expected, message) {
  try {
    assert.strictEqual(actual, expected, message);
  } catch (err) {
    const detail = message ? `${message}: ` : '';
    throw new Error(`${detail}Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function assertContains(haystack, needle, message) {
  const contains = typeof haystack === 'string'
    ? haystack.includes(needle)
    : Array.isArray(haystack) ? haystack.includes(needle) : false;
  if (!contains) {
    const detail = message ? `${message}: ` : '';
    throw new Error(`${detail}Expected target to contain ${JSON.stringify(needle)}`);
  }
}

function assertNotContains(haystack, needle, message) {
  const contains = typeof haystack === 'string'
    ? haystack.includes(needle)
    : Array.isArray(haystack) ? haystack.includes(needle) : false;
  if (contains) {
    const detail = message ? `${message}: ` : '';
    throw new Error(`${detail}Expected target NOT to contain ${JSON.stringify(needle)}`);
  }
}

function assertMatch(str, regex, message) {
  if (!regex.test(str)) {
    const detail = message ? `${message}: ` : '';
    throw new Error(`${detail}Expected ${JSON.stringify(str)} to match ${regex.toString()}`);
  }
}

function assertHeader(headers, headerName, expectedValue, message) {
  const actualValue = headers[headerName.toLowerCase()];
  if (actualValue === undefined) {
    throw new Error(`${message || 'Header check'}: Expected header "${headerName}" was not found on response.`);
  }
  if (expectedValue instanceof RegExp) {
    if (!expectedValue.test(actualValue)) {
      throw new Error(`${message || 'Header check'}: Header "${headerName}" value "${actualValue}" did not match pattern ${expectedValue}`);
    }
  } else if (expectedValue !== undefined) {
    if (actualValue.toLowerCase() !== expectedValue.toLowerCase()) {
      throw new Error(`${message || 'Header check'}: Header "${headerName}" expected "${expectedValue}", got "${actualValue}"`);
    }
  }
}

module.exports = {
  assertEqual,
  assertContains,
  assertNotContains,
  assertMatch,
  assertHeader,
};
