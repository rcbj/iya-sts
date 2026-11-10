// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: BUSL-1.1
'use strict';

// ===========================================================================
// THE DATABASE PASSWORDS OF THE COMPOSE STACK ARE GENERATED AT FIRST START.
//
// docker-compose.yml defaults to product mode, and product mode refuses to
// start on a well-known database password. So a password written in that file
// is a stack that does not come up, and the run-tests stack, which opts out,
// cannot show it. These checks read the file for what must be absent and run
// the script for what it must do.
// ===========================================================================

const childProcess = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const root = path.join(__dirname, '..');
const script = path.join(root, 'postgres', 'db-secrets.sh');

function source(dir, env) {
  const printer = '. "' + script + '"; ' +
    'printf "%s %s %s" "$POSTGRES_PASSWORD" "$STS_DB_APP_PASSWORD" "$(umask)"';
  const out = childProcess.execFileSync('bash', ['-c', printer], {
    env: Object.assign({ PATH: process.env.PATH, STS_DB_SECRETS_DIR: dir },
                       env || {}),
    encoding: 'utf8',
  });
  const parts = out.split(' ');
  return { owner: parts[0], app: parts[1], umask: parts[2] };
}

function run(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'db-secrets-'));
  const compose = fs.readFileSync(path.join(root, 'docker-compose.yml'),
                                  'utf8');
  try {
    t.check(!/POSTGRES_PASSWORD=/.test(compose),
            'docker-compose.yml assigns the owner no password');
    t.check(!/STS_DB_APP_PASSWORD=/.test(compose),
            'docker-compose.yml assigns the service role no password');
    t.check(/\. \/usr\/local\/bin\/db-secrets\.sh &&/.test(compose),
            'the database container sources the generator first');
    t.check(/- sts-db-secrets:\/run\/sts-db-secrets:ro/.test(compose),
            'the seeder reads the generated password, read-only');

    const first = source(dir);
    t.check(/^[0-9a-f]{64}$/.test(first.owner),
            'the owner password is 256 random bits');
    t.check(/^[0-9a-f]{64}$/.test(first.app) && first.app !== first.owner,
            'the service role has a different one');
    t.check((fs.statSync(path.join(dir, 'app')).mode & 0o077) === 0,
            'the file is readable by its owner alone');

    const again = source(dir);
    t.check(again.owner === first.owner && again.app === first.app,
            'a restart keeps the passwords the database was created with');

    const set = source(dir, { STS_POSTGRES_PASSWORD: 'chosen-owner',
                              STS_DB_APP_PASSWORD: 'chosen-app' });
    t.check(set.owner === 'chosen-owner' && set.app === 'chosen-app',
            'a value the deployment set wins');

    const before = childProcess.execFileSync(
      'bash', ['-c', 'umask'], { encoding: 'utf8' }).trim();
    t.equal(first.umask, before,
            'the umask does not leak into the certificate step');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

module.exports = {
  name: 'compose_db_passwords',
  describe: 'the compose stack generates its database passwords at first start',
  run: run
};
