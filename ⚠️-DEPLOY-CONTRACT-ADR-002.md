> **⚠️ ADR-002 (2026-07-16) — obfuscated 是部署约束**
>
> 本仓存在两份源码:
> - `明文源吗` (8960 行, **仅供审计参考**)
> - `少年你相信光吗` / `worker.deploy.mjs` (1.6MB obfuscated, **生产部署用**)
>
> **不要**让 deployer cp `明文源吗`。部署契约要求 obfuscated 版本,
> deployer 已加 line_count assertion (cf-regress-geo-pages.mjs:236), cp 明文会 throw。
>
> 审计路径: 黑盒 + `wrangler tail` + `tcpdump` + `wscat`
> 详见 `cfnew-deployer/docs/obfuscated-blackbox-verification.md` 或 `.kallax/decisions/ADR-002`。