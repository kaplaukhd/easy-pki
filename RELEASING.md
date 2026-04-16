# Releasing easy-pki

Maintainer-only guide. Users should never need to read this.

## Target

`easy-pki` publishes to **Maven Central** via Sonatype Central Portal, using
the [`central-publishing-maven-plugin`](https://central.sonatype.org/publish/publish-portal-maven/).

Coordinates:

- **groupId:** `io.github.kaplaukhd`
- **Artifacts:** `easy-pki-core`, `easy-pki-validation`,
  `easy-pki-spring-boot-starter`, `easy-pki-test`

## One-time setup

### 1. Sonatype Central Portal account

1. Create an account at <https://central.sonatype.com>.
2. Verify ownership of the `io.github.kaplaukhd` namespace (GitHub-based
   namespace — confirmed automatically once the account is linked to the
   matching GitHub user).
3. Generate a user token (Account → "Generate User Token") — you get a
   `username` and `password`.

### 2. Maven settings

Add to `~/.m2/settings.xml`:

```xml
<settings>
  <servers>
    <server>
      <id>central</id>
      <username>YOUR_PORTAL_TOKEN_USERNAME</username>
      <password>YOUR_PORTAL_TOKEN_PASSWORD</password>
    </server>
  </servers>
</settings>
```

The `id` **must** be `central` — it matches `publishingServerId` in
[pom.xml](pom.xml).

### 3. GPG key

Every artifact on Maven Central must be GPG-signed.

```bash
gpg --full-generate-key          # RSA 4096, no expiry, protect with a passphrase
gpg --list-secret-keys           # note the key ID
gpg --keyserver keys.openpgp.org --send-keys <KEY_ID>
gpg --keyserver keyserver.ubuntu.com --send-keys <KEY_ID>
```

Export the passphrase to Maven:

```xml
<profiles>
  <profile>
    <id>release-signing</id>
    <properties>
      <gpg.keyname>YOUR_KEY_ID</gpg.keyname>
      <gpg.passphrase>YOUR_PASSPHRASE</gpg.passphrase>
    </properties>
  </profile>
</profiles>

<activeProfiles>
  <activeProfile>release-signing</activeProfile>
</activeProfiles>
```

## Dry run

Produce the full release bundle locally, signing skipped:

```bash
mvn clean verify -Prelease -Dgpg.skip=true -DskipTests
```

Each module should produce three JARs:

- `<artifactId>-<version>.jar`
- `<artifactId>-<version>-sources.jar`
- `<artifactId>-<version>-javadoc.jar`

Inspect them quickly:

```bash
for m in easy-pki-core easy-pki-validation easy-pki-spring-boot-starter easy-pki-test; do
    ls -la $m/target/*.jar
done
```

## Release

1. **Update `CHANGELOG.md`** — move `Unreleased` entries under a dated
   `[1.0.0] - YYYY-MM-DD` heading. Commit.

2. **Bump version** in every `pom.xml` from `1.0.0-SNAPSHOT` to `1.0.0`:

   ```bash
   find . -name pom.xml -not -path '*/target/*' \
     -exec sed -i '' 's/1.0.0-SNAPSHOT/1.0.0/g' {} +
   mvn clean verify
   git commit -am "chore(release): 1.0.0"
   ```

3. **Sign and publish:**

   ```bash
   mvn clean deploy -Prelease -DskipTests
   ```

   The `central-publishing-maven-plugin` uploads signed bundles to the
   Portal's staging area. `autoPublish=false` in our POM means the release
   is **not** published automatically — you get a chance to verify in the
   Portal UI.

4. **Promote the release** at <https://central.sonatype.com/publishing> —
   click "Publish" once the validation checks are green. It takes ~15
   minutes to propagate to Maven Central and a few hours to appear in
   search.

5. **Tag and push:**

   ```bash
   git tag -a v1.0.0 -m "easy-pki 1.0.0"
   git push origin main --tags
   ```

6. **Create a GitHub Release** from the tag, pasting the changelog
   section for this version.

7. **Bump to the next SNAPSHOT:**

   ```bash
   find . -name pom.xml -not -path '*/target/*' \
     -exec sed -i '' 's/1.0.0/1.1.0-SNAPSHOT/g' {} +
   git commit -am "chore(release): bump to 1.1.0-SNAPSHOT"
   git push
   ```

## Troubleshooting

- **`Failed to deploy: 401 Unauthorized`** — the `<server id="central">`
  credentials in `~/.m2/settings.xml` don't match a valid Portal token.
- **`gpg: signing failed: Inappropriate ioctl for device`** — export
  `GPG_TTY=$(tty)` in your shell, or set `pinentry-program` in
  `gpg-agent.conf`.
- **Validation fails in the Portal UI** — the error message usually
  points at a specific artifact. Most common causes: missing javadoc
  JAR, missing sources JAR, POM missing `<name>/<description>/<url>/
  <licenses>/<developers>/<scm>`. All of these are emitted by our
  release profile; if something is missing, check the child POM
  inherited from the parent correctly.
