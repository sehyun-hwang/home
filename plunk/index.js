import {
  appendRemote,
  addRemoteEventListener,
  setPositions,
} from './remote.js';
import handleAuth from './auth.js';
import { subscribeAppSync } from './amplify.js';

const statusElement = document.querySelector('#status');
const remoteElement = document.querySelector('#remote');

const eventTarget = new EventTarget();

const handleStatus = (res) =>
  (res.ok ? res.json() : Promise.reject(res.json()))
    .then(({ requestId, html }) => {
      console.log(requestId);
      const doc = new DOMParser().parseFromString(html, 'text/html');
      const message = `${
        doc.querySelector('h1')?.textContent || html
      }: ${requestId}`;

      console.log(message);
      statusElement.textContent = message;

      return new Promise((resolve, reject) => {
        setTimeout(reject, 3000, new Error('Timeout'));
        eventTarget.addEventListener(
          'message',
          ({ detail }) => detail.requestId === requestId && resolve(detail)
        );
      }).then(() => (statusElement.textContent = 'IR fired: ' + requestId));
    })
    .catch(async (asyncError) => {
      const error = await asyncError;
      console.error(res, error);
      statusElement.textContent = error.message;
    });

Promise.all(
  Array.prototype.map.call(
    document.querySelectorAll('link[rel="preload"]'),
    (link) => {
      console.log(link);
      return appendRemote(link.href, remoteElement);
    }
  )
).then(setPositions);
// fetch(API + "status").then(handleStatus);

handleAuth(remoteElement).then(({ idToken, llamaLab }) => {
  console.log(idToken);
  addRemoteEventListener(remoteElement, llamaLab, handleStatus);
  subscribeAppSync(eventTarget);
});
