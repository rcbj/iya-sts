'use strict';
//
// File: deploy/aws/runner/upload-report.js
//
// ---------------------------------------------------------------------------
// UPLOADS ONE FILE TO THE REPORT BUCKET (issue #51), for run-in-task.sh:
//
//   node deploy/aws/runner/upload-report.js <file> <bucket> <key> [content-type]
//
// The S3 client is the one package the runner image adds (/opt/sts-runner);
// credentials come from the task role through the SDK's default chain.
//
// Its `log` is console-backed and bunyan-shaped, the arrangement the root
// CLAUDE.md names for a file that does not load the service's logger: this
// runs once per upload in a container that has no appconfig file to read.
// ---------------------------------------------------------------------------
const fs = require('fs');
const path = require('path');
const { S3Client, PutObjectCommand } =
  require(path.join('/opt/sts-runner/node_modules/@aws-sdk/client-s3'));

const log = {
  debug: function (message) {
    if (process.env.LOG_LEVEL === 'debug') {
      process.stderr.write(message + '\n');
    }
  }
};

async function main() {
  log.debug('Entering main().');
  const [file, bucket, key, type] = process.argv.slice(2);
  if (!file || !bucket || !key) {
    log.debug('Leaving main().');
    throw new Error('usage: upload-report.js <file> <bucket> <key> [type]');
  }
  const client = new S3Client({ region: process.env.AWS_REGION });
  await client.send(new PutObjectCommand({
    Bucket: bucket,
    Key: key,
    Body: fs.readFileSync(file),
    ContentType: type || 'application/octet-stream'
  }));
  process.stdout.write('uploaded s3://' + bucket + '/' + key + '\n');
  log.debug('Leaving main().');
}

main().catch(function (e) {
  process.stderr.write('upload-report: ' + ((e && e.message) || e) + '\n');
  process.exit(1);
});
