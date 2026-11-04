// Validate real SorobanShield JSON reports with the existing AJV dependency.
import { readFileSync } from 'node:fs'
import Ajv from 'ajv'

const [schemaPath, ...files] = process.argv.slice(2)
if (!schemaPath || files.length === 0) {
  console.error('usage: node validate-report.mjs <schema.json> <report.json>...')
  process.exit(2)
}
const validate = new Ajv({ allErrors: true }).compile(JSON.parse(readFileSync(schemaPath, 'utf8')))
let failed = false
for (const file of files) {
  const report = JSON.parse(readFileSync(file, 'utf8'))
  if (validate(report)) {
    console.log(`ok    ${file}`)
  } else {
    failed = true
    console.error(`FAIL  ${file}: ${JSON.stringify(validate.errors)}`)
  }
}
// Every checked-in fixture has to pass; test that incorrect types and missing
// required fields fail independently so a permissive schema cannot pass CI.
const good = JSON.parse(readFileSync(files[0], 'utf8'))
for (const [label, mutate] of [
  ['wrong schema_version type', r => { r.schema_version = '1' }],
  ['missing required findings', r => { delete r.findings }],
  ['wrong summary count type', r => { r.summary.total = '0' }],
  ['invalid finding severity', r => { r.findings = [{rule_id:'SS-001',title:'x',severity:'extreme',confidence:'low',message:'x',file:'x',start_line:null,end_line:null,remediation:'x',references:[],limitations:[]}] }],
]) {
  const broken = structuredClone(good)
  mutate(broken)
  if (validate(broken)) {
    failed = true
    console.error(`FAIL: schema accepted ${label}`)
  } else {
    console.log(`ok    rejected ${label}`)
  }
}
process.exit(failed ? 1 : 0)
