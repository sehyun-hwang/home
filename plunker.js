import { CloudFrontClient, CreateInvalidationCommand } from '@aws-sdk/client-cloudfront';
import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { JSDOM } from 'jsdom';
import mime from 'mime';

const PLUNKER_URL = 'https://plnkr.co/edit/vS3ScYhHIzOeDP87?preview';
const Bucket = 'hwangsehyun';
const PROJECT_PREFIX = 'home/';
const DistributionId = 'E2B4OCMR138KKR';

const s3Client = new S3Client({
  region: 'ap-southeast-1',
});
const cloudfrontClient = new CloudFrontClient();

const fetchPlunkerSource = () => JSDOM.fromURL(PLUNKER_URL)
  .then(dom => {
    let script;
    for (script of dom.window.document.head.querySelectorAll('script'));
    return JSON.parse(script.textContent.replace('window._ssr =', ''));
  });

await fetchPlunkerSource()
  .then(({ plunk: { entries, ...plunk } }) => {
    console.log(plunk);
    // console.log(entries);
    return Promise.all(entries.map(({ content: Body, pathname }) => s3Client
      .send(new PutObjectCommand({
        Bucket,
        Key: PROJECT_PREFIX + pathname,
        ContentType: mime.getType(pathname),
        Body,
      }))));
  })
  .then(() => cloudfrontClient.send(new CreateInvalidationCommand({
    DistributionId,
    InvalidationBatch: {
      CallerReference: `${+new Date()}`,
      Paths: {
        Quantity: 1,
        Items: [`/${PROJECT_PREFIX}*`],
      },
    },
  })))
  .then(console.log);

console.log('Done');
