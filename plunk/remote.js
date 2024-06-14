import { PublishQuery } from './amplify.js';

const parser = new DOMParser();

const getButtons = (dom) =>
  Array.prototype.map.call(dom.querySelectorAll('button'), (x) => {
    const button = document.createElement('button');
    const label = x.getAttribute('label');
    button.textContent = label;
    button.value = label;
    button.style.gridColumn = `span ${x.getAttribute('span') || 1}`;
    const background = x.getAttribute('backgroundColor');
    if (background) button.style.backgroundColor = '#' + background.slice(2);

    const ir = JSON.stringify(x.textContent.split(' ').map(Number));
    console.log(x, ir);
    Object.assign(button.dataset, {
      ir,
      progress: 0,
    });

    return button;
  });

let appendRemotePromise = Promise.resolve();
export const appendRemote = (xml, remoteElement) =>
  (appendRemotePromise = appendRemotePromise
    .then(() => fetch(xml))
    .then((res) => res.text())
    .then((text) => parser.parseFromString(text, 'application/xml'))
    .then((dom) => {
      const device = dom.querySelector('device');
      if (device.getAttribute('format') !== 'WINLIRC_RAW')
        throw new Error('Unsupported format: ' + device.getAttribute('format'));

      const id = 'remote-' + xml.replace('.xml', '');
      const element = document.createElement('section');
      element.id = id;
      element.style.gridTemplateColumns = `repeat(${device.getAttribute(
        'columns'
      )}, 1fr)`;

      const a = document.createElement('a');
      a.href = '#' + id;
      const heading = document.createElement('h3');
      heading.textContent = `${device.getAttribute(
        'manufacturer'
      )} ${device.getAttribute('model')}`;

      console.groupCollapsed(xml);
      const buttons = getButtons(dom);
      buttons.forEach((button) => element.appendChild(button));
      console.groupEnd(xml);

      a.appendChild(heading);
      remoteElement.appendChild(a);
      remoteElement.appendChild(element);
      return heading;
    }));

export function setPositions(headings) {
  console.log(headings);
  headings.forEach((heading, i) => {
    heading.parentElement.nextElementSibling.style.scrollMarginTop =
      2 * (i + 1) + 'rem';
    heading.style.top = 2 * i + 'rem';
  });

  headings.reverse();
  headings.forEach((heading, i) => {
    heading.parentElement.nextElementSibling.style.scrollMarginBottom =
      2 * i + 'rem';
    heading.style.bottom = 2 * i + 'rem';
  });
}

export async function addRemoteEventListener(
  remoteElement,
  llamaLab,
  handleStatus
) {
  console.log('Adding event listener to remote', remoteElement);

  remoteElement.addEventListener('click', ({ target }) => {
    if (target.tagName !== 'BUTTON') return;
    console.log(target);
    navigator.vibrate(100);
    target.dataset.progress++;
    requestIR(target, llamaLab, handleStatus);
  });
}

function requestIR(button, { authorization, headers, params }, handleStatus) {
  const body = new URLSearchParams({
    ...params,
    payload: `{"query":${JSON.stringify(PublishQuery)},"ir":${
      button.dataset.ir
    },"authorization":"${authorization}"}`,
  });

  return fetch(
    'https://xob8fd1ovj.execute-api.ap-northeast-1.amazonaws.com/default/home/llamalab',
    {
      method: 'POST',
      headers,
      body,
    }
  )
    .then(handleStatus)
    .then(console.log)
    .then(() => button.classList.add('success'))
    .catch((error) => {
      button.classList.add('failure');
      console.error(error);
    })
    .finally(() => {
      button.dataset.progress--;
      setTimeout(() => button.classList.remove('success', 'failure'), 200);
    });
}
