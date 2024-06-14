import PatternLock from 'https://cdn.jsdelivr.net/npm/patternlock@2.0.2/dist/patternlock.es.js';
import calculateHash from 'https://cdn.jsdelivr.net/npm/crypto-js@4.1.1/md5.js/+esm';
import Base64 from 'https://cdn.jsdelivr.net/npm/crypto-js@4.1.1/enc-base64/+esm';

import { username } from './amplify.js';
import { fetchAuthSession, signIn } from './dist.js';
console.log('username', username);

const elementId = '#patternlock';
const mapper = ' qweasdzxc'.split('');
let lock, onDraw;

const keydownHandler = ({ key }) => {
  console.log(key);
  const ACTION = {
    Escape: lock.reset,
    Enter: onDraw,
  };
  const action = ACTION[key];
  if (action) return action(lock.getPattern());

  const index = mapper.indexOf(key);
  if (lock && index > 0);
  else return;
  const pattern = lock.getPattern() + index;
  console.log(pattern);
  lock.setPattern(pattern);
};

function createSession(pattern) {
  const password = Base64.stringify(calculateHash(pattern));
  console.log(pattern, password);
  return signIn({ username, password }).then(fetchAuthSession);
}

function onDrawFactory(lockElement, resolve, pattern) {
  lock.disable();

  createSession(pattern)
    .then(resolve)
    .then(() => {
      lockElement.style.display = 'none';
      window.removeEventListener('keydown', keydownHandler);
    })
    .catch((error) => {
      console.error(error);
      lock.error();
    })
    .finally(lock.enable.bind(lock));
}

const authenticatePatternLock = () => {
  window.addEventListener('keydown', keydownHandler);

  let resolve;
  const promise = new Promise((_resolve) => (resolve = _resolve));
  onDraw = onDrawFactory.bind(
    undefined,
    document.querySelector(elementId),
    resolve
  );

  lock = new PatternLock(elementId, {
    onDraw,
    enableSetPattern: true,
  });
  console.log(lock);

  return promise;
};

export default async (remoteElement) => {
  let session = await fetchAuthSession();
  if (!session.tokens) session = await authenticatePatternLock();
  console.log(session);
  remoteElement.style.filter = 'unset';

  const {
    tokens: { idToken },
  } = session;
  const {
    payload: { email, ['custom:llamalab-secret']: Authorization },
  } = idToken;

  return {
    idToken: idToken.toString(),
    llamaLab: {
      authorization: idToken.toString(),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization,
        'X-Aws-Authorization': `Bearer ${idToken}`,
      },
      params: {
        to: email.replace(/\+(.*)\@/, '@'),
        device: '',
        priority: 'normal',
      },
    },
  };
};
