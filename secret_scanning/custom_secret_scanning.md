# [GitHub Advanced Security - Custom Patterns for Secret Scanning](https://docs.github.com/en/enterprise-cloud@latest/code-security/secret-scanning/)

## Below is a list of my custom set of (Regular) Regex expressions for custom patterns for matching secrets:

* `(?:\\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,}`: **`Artifactory_API_Token`**,
* `(?:\\s|=|:|\"|^)AP[\\dABCDEF][a-zA-Z0-9]{8,}`: **`Artifactory_Password`**,
* `basic: [a-zA-Z0-9_\\\\\\-:\\\\.=]+`: **`Authorization_Basic`**,
* `bearer: [a-zA-Z0-9_\\-\\.=]+`: **`Authorization_Bearer`**,
* `(?i:\\bBEGIN\\s(RSA|DSA|EC|OPENSSH)\\sPRIVATE\\sKEY\\b)`: **`Private_Key`**,
* `(?i:\\bBEGIN\\sPGP\\sPRIVATE\\sKEY\\sBLOCK\\b)`: **`PGP_Private_Key`**,
* `[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]`: **`Generic_API_Key`**,
* `[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]`: **`Generic_Secret`**,
* `(?i:\\bxox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}\\b)`: **`AWS_API_Key`**,
* `(?i:\\bamzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b)`: **`AWS_MWS_Key`**,
* `(?i:\\bAKIA[0-9A-Z]{16}\\b)`: **`AWS_API_ID`**,
* `(?i:\\bASIA[0-9A-Z]{16}\\b)`: **`AWS_API_ID_EXPIRED`**,
* `cloudinary://.*`: **`Cloudinary`**,
* `EAACEdEose0cBA[0-9A-Za-z]+`: **`Facebook_Access_Token`**,
* `[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]`: **`Facebook_OAuth`**,
* `[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]`: **`GitHub`**,
* `(?i:\\gGHP)`: **`GitHub_GHP_PAT`**,
* `(?i:\\b[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com\\b)`: **`Google_API_Key`**,
* `AIza[0-9A-Za-z\\-_]{35}`: **`Google_YouTube_API_Key`**,
* `[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com`: **`Google_YouTube_OAuth`**,
* `\"type\": \"service_account\"`: **`Google_GCP_Service_account`
* `ya29\\.[0-9A-Za-z\\-_]+`: **`Google_OAuth_Access_Token`**,
* `[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`: **`Heroku_API_Key`**,
* `[0-9a-f]{32}-us[0-9]{1,2}`: **`MailChimp_API_Key`**,
* `key-[0-9a-zA-Z]{32}`: **`Mailgun_API_Key`**,
* `[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]`: **`Password_in_URL`**,
* `access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}`: **`PayPal_Braintree_Access_Token`**,
* `sk_live_[0-9a-z]{32}`: **`Picatic_API_Key`**,
* `(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})`: **`Slack_Token`**,
* `https:\\/\\/hooks.slack.com\\/services\\/T[a-zA-Z0-9_]{10}\\/B[a-zA-Z0-9_]{10}\\/[a-zA-Z0-9]{24}`: **`Slack_Webhook`**,
* `sk_live_[0-9a-zA-Z]{24}`: **`Stripe_API Key`**,
* `rk_live_[0-9a-zA-Z]{24}`: **`Stripe_Restricted_API_Key`**,
* `sq0atp-[0-9A-Za-z\\-_]{22}`: **`Square_Access_Token`**,
* `sq0csp-[0-9A-Za-z\\-_]{43}`: **`Square_OAuth_Secret`**,
* `SK[0-9a-fA-F]{32}`: **`Twilio_API_Key`**,
* `[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}`: **`Twitter_Access_Token`**,
* `[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]`: **`Twitter_OAuth`**,
* `(?i)(?:codecov)(?:[0-9a-z\\\\-_\\t .]{0,20})(?:[\\\\s|']|[\\\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}([a-z0-9]{32})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`Codecov_Access_Token`**,
* `(?i)(?:coinbase)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}([a-z0-9_-]{64})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`Coinbase_Access_Token`**,
* `(?i)(?:confluent)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}([a-z0-9]{16})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`Confluent_Access_Token`**,
* `(?i)(?:confluent)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}([a-z0-9]{64})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`Confluent_Access_Key`**,
* `(?i)\\b(dapi[a-h0-9]{32})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`Databricks_API_Token`**,
* `(?i)(?:datadog)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}([a-z0-9]{40})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`Datadog_Access_Token`**,
* `(?i)\\b(dop_v1_[a-f0-9]{64})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`DigitalOcean_PAT`**,
* `(?i)\\b(doo_v1_[a-f0-9]{64})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`DigitalOcean_OAUTH_Token`**,
* `(?i)\\b(dor_v1_[a-f0-9]{64})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`DigitalOcean_OAUTH_Refresh_Token`**,
* `(?i)(?:discord)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}([a-f0-9]{64})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`Discord_API_Key`**,
* `(?i)(?:discord)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}([0-9]{18})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`Discord_Client_ID`**,
* `(?i)(?:discord)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}([a-z0-9=_\\-]{32})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`Discord_Client_Secret`**,
* `(?i)(?:dropbox)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}([a-z0-9]{15})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`DropBox_API_Secret`**,
* `(?i)(?:dropbox)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\\-_=]{43})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`DropBox_API_Token`**,
* `(?i)(?:dropbox)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}(sl\\.[a-z0-9\\-=_]{135})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`DropBox_API_Token_2`**,
* `(?i)(?:fastly)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}([a-z0-9=_\\-]{32})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`Fastly_API_Key`**,
* `ghp_[0-9a-zA-Z]{36}`: **`GitHub_GHP_PAT_2`**,
* `ghr_[0-9a-zA-Z]{36}`: **`GitHub_Refresh_Token`**,
* `glpat-[0-9a-zA-Z\\-\\_]{20}`: **`GitLab_PAT`**,
* `(?i)\\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,2})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`Grafana_API_Key`**,
* `(?i)\\b(glc_[A-Za-z0-9+/]{32,400}={0,2})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`Grafana_Cloud_API_Key`**,
* `(?i)\\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`Grafana_Service_Account_Token`**,
* `(?i)[a-z0-9]{14}\\.atlasv1\\.[a-z0-9\\-_=]{60,70}`: **`HashiCorp_Terraform_API_Token`**,
* `(?i)(?:heroku)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`Heroku_API_Key_2`**,
* `(?i)\\b(ey[0-9a-z]{30,34}\\.ey[0-9a-z-\\/_]{30,500}\\.[0-9a-zA-Z-\\/_]{10,200}={0,2})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`JWT`**,
* `(?i)\\b(npm_[a-z0-9]{36})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`NPM_Access_Token`**,
* `(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}([a-z0-9]{64})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`New_Relic_User_API_`**,
* `(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}(NRAK-[a-z0-9]{27})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`New_Relic_User_IDKey`**,
* `(?i)(?:okta)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}([a-z0-9=_\\-]{42})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`OKTA_Access_Token`**,
* `(?i)\\b(PMAK-(?i)[a-f0-9]{24}\\-[a-f0-9]{34})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`Postman_API_Token`**,
* `(?i)(?:sumo)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}([a-z0-9]{14})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`Sumo_Logic_Access_ID`**,
* `(?i)(?:sumo)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}([a-z0-9]{64})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`Sumo_Logic_Access_Token`**,
* `(?i)(?:travis)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}([a-z0-9]{22})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`Travis_CI_Access_Token`**,
* `(?i)\\b(hvb\\.[a-z0-9_-]{138,212})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`HCP_Vault_Batch_Token`**,
* `(?i)\\b(hvs\\.[a-z0-9_-]{90,100})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)`: **`HCP_Vault_Service_Token`**,
* `https:\\/\\/[a-z]{1,10}-[a-z]{1,10}-[0-9]{4}.tines.com`: **`Tines_Tenant`**,
* `https:\\/\\/[a-z]{1,10}-[a-z]{1,10}-[0-9]{4}.tines.com\\/webhook\\/[a-z0-9]{32}\\/[a-z0-9]{32}`: **`Tines_Webhook`**

## To convert a regular expression to a Hyperscan regular expression, you can follow these steps:

1. Remove any enclosing quotes around the regular expression.
2. Remove any capturing groups from the regular expression.
3. Remove any non-capturing groups from the regular expression.
4. Remove any parentheses from the regular expression.
5. Replace any character classes with their corresponding Hyperscan regular expression.
6. Remove any backslashes before special characters (\, ^, $, ., |, ?, *, +, (, ), [, {, and }), unless they are needed to escape a character in the regular expression.
7. Replace any repeating groups with their corresponding Hyperscan regular expression.
8. Replace any special characters with their corresponding Hyperscan regular expression.
9. Add any Hyperscan-specific flags to the regular expression, such as case-insensitivity or dotall mode, if needed.
10. Use the modified regular expression in Hyperscan functions such as `hs_compile` and `hs_scan`.
