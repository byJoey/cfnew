import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

async function 加载明文模块() {
  const 原始源码 = await readFile(new URL('../明文源吗', import.meta.url), 'utf8');
  const 临时目录 = await mkdtemp(join(tmpdir(), 'cfnew-geo-prefix-'));
  const 临时文件 = join(临时目录, '明文源吗.testable.mjs');
  const 可测试源码 = 原始源码
    .replace("import { connect as 连接 } from 'cloudflare:sockets';", 'const 连接 = globalThis.__CF_CONNECT_STUB__;')
    .replace('export default {', 'const __worker_default__ = {');

  await writeFile(临时文件, 可测试源码, 'utf8');
  try {
    return await import(`${pathToFileURL(临时文件).href}?t=${Date.now()}`);
  } finally {
    await rm(临时目录, { recursive: true, force: true });
  }
}

test('域名优选节点使用真实 IP 归属地前缀', async () => {
  const { 创建值节点命名器, 附加地区前缀到列表 } = await 加载明文模块();
  const 列表 = await 附加地区前缀到列表([{
    ip: 'speed.example.com',
    isp: '优选域名'
  }], {
    解析域名: async () => '1.1.1.1',
    查询归属地: async () => ({ countryCode: 'SG', country: 'Singapore' })
  });
  const 制作节点名称 = 创建值节点命名器(false);
  assert.equal(制作节点名称(列表[0]), '🇸🇬新加坡-优选域名-01');
});

test('归属地查询失败时回退到原始命名', async () => {
  const { 创建值节点命名器, 附加地区前缀到列表 } = await 加载明文模块();
  const 列表 = await 附加地区前缀到列表([{
    ip: 'speed.example.com',
    isp: '优选域名'
  }], {
    解析域名: async () => '1.1.1.1',
    查询归属地: async () => null
  });
  const 制作节点名称 = 创建值节点命名器(false);
  assert.equal(制作节点名称(列表[0]), '优选域名-01');
});

test('同一个真实 IP 在一次生成流程中只查询一次', async () => {
  const { 附加地区前缀到列表 } = await 加载明文模块();
  let 查询次数 = 0;
  await 附加地区前缀到列表([{
    ip: 'sg-1.example.com',
    isp: '优选域名'
  }, {
    ip: 'sg-2.example.com',
    isp: '优选域名'
  }], {
    解析域名: async () => '1.1.1.1',
    查询归属地: async () => {
      查询次数++;
      return { countryCode: 'SG', country: 'Singapore' };
    }
  });
  assert.equal(查询次数, 1);
});

test('已带地区前缀的上游名称保持原样', async () => {
  const { 创建值节点命名器 } = await 加载明文模块();
  const 制作节点名称 = 创建值节点命名器(false);
  assert.equal(
    制作节点名称({ name: '🇸🇬新加坡-优选节点-11', geoPrefix: '', ip: '1.1.1.1' }),
    '🇸🇬新加坡-优选节点-11'
  );
});

test('带显式地区语义的 ProxyIP 名称保持原样', async () => {
  const { 创建值节点命名器 } = await 加载明文模块();
  const 制作节点名称 = 创建值节点命名器(false);
  assert.equal(
    制作节点名称({ name: '🇭🇰香港-ProxyIP-HK-01', regionCode: 'HK', ip: 'proxy.example.com' }),
    '🇭🇰香港-ProxyIP-HK-01'
  );
});

test('yx-tools 旧格式测速名称会归一化为优选节点命名', async () => {
  const { 创建值节点命名器 } = await 加载明文模块();
  const 制作节点名称 = 创建值节点命名器(false);
  assert.equal(
    制作节点名称({ name: '新加坡-12.34MB/s', ip: '1.1.1.1', geoPrefix: '🇸🇬新加坡' }),
    '🇸🇬新加坡-优选节点-01'
  );
});

test('ProxyIP 名称缺少显式地区时仍按现有 fallback 逻辑命名', async () => {
  const { 创建值节点命名器 } = await 加载明文模块();
  const 制作节点名称 = 创建值节点命名器(false);
  assert.equal(
    制作节点名称({ isp: 'ProxyIP-SG', ip: '1.1.1.1', geoPrefix: '' }),
    'ProxyIP-SG-01'
  );
});
