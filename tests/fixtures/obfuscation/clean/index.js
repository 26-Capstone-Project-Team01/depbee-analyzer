'use strict';

const { formatGreeting } = require('./lib/format');

/**
 * 인사말을 만들어 반환한다. 부수 효과는 없다.
 */
function greet(name) {
  if (typeof name !== 'string' || name.length === 0) {
    return formatGreeting('world');
  }
  return formatGreeting(name);
}

module.exports = { greet };
