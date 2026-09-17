import { FlamingoWorker } from './client.js';

const form = document.querySelector('#match');
const status = document.querySelector('#status');
const submit = form.querySelector('[type=submit]');
let active;
document.querySelector('#cancel').onclick = () => active?.close('Cancelled');
form.onsubmit = async event => {
  event.preventDefault();
  const client = new FlamingoWorker();
  active = client;
  submit.disabled = true;
  status.textContent = 'Loading and verifying…';
  try {
    const data = new FormData(form);
    const input = { matchThreshold: Number(data.get('matchThreshold')) };
    for (const name of ['liveImage', 'credentialImage', 'hashesJson', 'challengeImage']) {
      input[name] = new Uint8Array(await data.get(name).arrayBuffer());
    }
    await client.initialize({
      hostUrl: data.get('hostUrl'),
      measurements: { 0: data.get('pcr0'), 1: data.get('pcr1'), 2: data.get('pcr2') },
    });
    const result = await client.match(input);
    status.textContent = result.matched
      ? 'Signed match verified. World ID proof generation is a separate integration.'
      : `Match rejected: ${result.rejection} (unsigned rejection).`;
  } catch (error) {
    status.textContent = error.message;
  } finally {
    client.close();
    active = undefined;
    submit.disabled = false;
  }
};
