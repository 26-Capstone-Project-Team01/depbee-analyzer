'use strict';

const GREETING_PREFIX = 'Hello';

function formatGreeting(name) {
  return GREETING_PREFIX + ', ' + name + '!';
}

module.exports = { formatGreeting };
