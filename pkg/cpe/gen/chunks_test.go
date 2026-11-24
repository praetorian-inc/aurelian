package main

// Real NVD records, verbatim, trimmed to the smallest set that exercises each
// behaviour. These replaced 2.7 MB of whole-feed chunks: the distiller inserts
// into a set per record with no counting, ranking or threshold anywhere, so
// 3,404 nginx records proved exactly what three do.
//
// What the record count DID matter for is the rename chain — `resolve` treats
// a successor absent from the chunk as live, so an extract that drops the
// middle of igor_sysoev -> nginx -> f5 records the deprecated vendor and the
// test passes for the wrong reason. Version 0.1.0 is used throughout because
// all three records exist at it in the real feed.

// nginxChunk is that chain. The first record keeps every field NVD publishes,
// including the several the parser ignores, so the schema tolerance the whole
// feed used to demonstrate is still demonstrated here.
const nginxChunk = `{"products":[
 {"cpe":{
   "deprecated":true,
   "cpeName":"cpe:2.3:a:igor_sysoev:nginx:0.1.0:*:*:*:*:*:*:*",
   "cpeNameId":"8BFA37A6-4985-4698-B593-6591E5EC6A18",
   "lastModified":"2019-02-28T20:20:43.033",
   "created":"2012-04-19T14:07:01.457",
   "titles":[{"title":"Nginx 0.1.0","lang":"en"}],
   "deprecatedBy":[{"cpeName":"cpe:2.3:a:nginx:nginx:0.1.0:*:*:*:*:*:*:*",
                   "cpeNameId":"0B65F51C-84CC-4106-B9A3-8F54E56594E6"}]}},
 {"cpe":{
   "deprecated":true,
   "cpeName":"cpe:2.3:a:nginx:nginx:0.1.0:*:*:*:*:*:*:*",
   "deprecatedBy":[{"cpeName":"cpe:2.3:a:f5:nginx:0.1.0:*:*:*:*:*:*:*"}]}},
 {"cpe":{
   "deprecated":false,
   "cpeName":"cpe:2.3:a:f5:nginx:0.1.0:*:*:*:*:*:*:*"}}
]}`

// nginxDeprecatedOnlyChunk holds the middle of the chain with no live record
// beside it. The successor is absent, which is the real feed's shape — f5's
// records live in other chunks — and the resolver must still land on f5.
const nginxDeprecatedOnlyChunk = `{"products":[
 {"cpe":{
   "deprecated":true,
   "cpeName":"cpe:2.3:a:nginx:nginx:0.1.0:*:*:*:*:*:*:*",
   "deprecatedBy":[{"cpeName":"cpe:2.3:a:f5:nginx:0.1.0:*:*:*:*:*:*:*"}]}}
]}`

// redisChunk carries two simultaneously live vendors for one product, which
// the table must keep both of.
const redisChunk = `{"products":[
 {"cpe":{"deprecated":false,"cpeName":"cpe:2.3:a:redis:redis:7.0.5:*:*:*:*:*:*:*"}},
 {"cpe":{"deprecated":false,"cpeName":"cpe:2.3:a:redislabs:redis:6.2.0:-:*:*:*:*:*:*"}}
]}`

// cveOpenJDKChunk is CVE-2009-0723 as NVD publishes it. It cites
// `cpe:2.3:a:sun:openjdk`, a vendor with no CPE dictionary record of any kind,
// which is the entire reason the CVE pass exists.
const cveOpenJDKChunk = `{"resultsPerPage":1,"totalResults":1,"format":"NVD_CVE","version":"2.0",
 "vulnerabilities":[{"cve":{"id":"CVE-2009-0723","configurations":[
  {"nodes":[{"operator":"OR","negate":false,"cpeMatch":[
    {"vulnerable":true,"criteria":"cpe:2.3:a:gimp:gimp:*:*:*:*:*:*:*:*",
     "versionEndExcluding":"2.9.2","matchCriteriaId":"28CB30F0-E3AF-490A-B05B-0947A2BF717B"},
    {"vulnerable":true,"criteria":"cpe:2.3:a:mozilla:firefox:3.1:beta1:*:*:*:*:*:*",
     "matchCriteriaId":"0F72BFD4-000D-4B07-8261-C9F6839AD150"},
    {"vulnerable":true,"criteria":"cpe:2.3:a:sun:openjdk:*:*:*:*:*:*:*:*",
     "versionEndIncluding":"7","matchCriteriaId":"3BD10277-3747-438E-BB0F-CC7E71602FC1"}]}]},
  {"nodes":[{"operator":"OR","negate":false,"cpeMatch":[
    {"vulnerable":true,"criteria":"cpe:2.3:a:littlecms:little_cms:*:*:*:*:*:*:*:*",
     "versionEndIncluding":"1.17","matchCriteriaId":"5DAF1951-51CA-4FCC-94EE-3713860D6598"}]}]}
 ]}}]}`
