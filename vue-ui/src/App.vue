<template>
  <div class="app-container" :dir="isRtl ? 'rtl' : 'ltr'">
    <!-- Header -->
    <div class="app-header">
      <h1>{{ t('title') }}</h1>
      <p>{{ t('subtitle') }}</p>
    </div>

    <!-- Language Switcher -->
    <div class="lang-switcher">
      <button 
        class="lang-btn" 
        :class="{ active: locale === 'zh' }"
        @click="setLocale('zh')"
      >
        中文
      </button>
      <button 
        class="lang-btn" 
        :class="{ active: locale === 'fa' }"
        @click="setLocale('fa')"
      >
        فارسی
      </button>
    </div>


    <!-- UUID Input -->
    <div class="ios-card">
      <h2 class="card-title">{{ t('uuidLabel') || '订阅密钥' }}</h2>
      <div class="form-group">
        <input 
          v-model="userUuid" 
          type="text" 
          class="ios-input" 
          :placeholder="t('uuidPlaceholder') || '请输入您的订阅密钥(UUID)'"
          @input="onUuidChange"
        />
        <p class="form-hint" style="color: var(--ios-secondary); font-size: 0.75rem;">
          {{ t('uuidHint') || '您的订阅密钥，用于生成专属订阅链接' }}
        </p>
      </div>
    </div>

    <!-- Client Selection -->
    <div class="ios-card">
      <h2 class="card-title">{{ t('selectClient') }}</h2>
      <div class="client-grid">
        <button 
          v-for="client in clients" 
          :key="client.id"
          class="client-btn"
          :class="{ selected: selectedClient === client.id }"
          @click="selectClient(client)"
        >
          {{ client.name }}
        </button>
      </div>
      <div v-if="subscriptionUrl" class="subscription-url">
        <div>{{ subscriptionUrl }}</div>
      </div>
    </div>

    <!-- System Status -->
    <div class="ios-card">
      <h2 class="card-title">{{ t('systemStatus') }}</h2>
      <div class="status-panel">
        <div class="status-item">
          <span class="status-label">{{ t('workerRegion') }}</span>
          <span class="status-value" :class="statusClass(regionStatus)">{{ regionStatus }}</span>
        </div>
        <div class="status-item">
          <span class="status-label">{{ t('detectionMethod') }}</span>
          <span class="status-value">{{ detectionMethod }}</span>
        </div>
        <div class="status-item">
          <span class="status-label">{{ t('proxyIPStatus') }}</span>
          <span class="status-value success">{{ t('proxyIPAvailable') }}</span>
        </div>
        <div class="status-item">
          <span class="status-label">{{ t('currentIP') }}</span>
          <span class="status-value">{{ t('smartSelection') }}</span>
        </div>
        <div class="status-item">
          <span class="status-label">ECH</span>
          <span class="status-value" :class="echStatusClass">{{ echStatus }}</span>
        </div>
        <div class="status-item">
          <span class="status-label">{{ t('regionMatch') }}</span>
          <span class="status-value success">{{ t('sameRegionIP') }}</span>
        </div>
      </div>
    </div>

    <!-- Config Management -->
    <div class="ios-card">
      <h2 class="card-title">{{ t('configManagement') }}</h2>
      
      <!-- KV Status -->
      <div class="kv-status" :class="kvStatusClass">
        {{ kvStatus }}
      </div>

      <!-- Region Selection -->
      <div class="form-group">
        <label class="form-label">{{ t('specifyRegion') }}</label>
        <select v-model="config.wk" class="ios-select" :disabled="!!config.p">
          <option value="">{{ t('autoDetect') }}</option>
          <option v-for="(name, code) in regionNames" :key="code" :value="code">
            {{ name }}
          </option>
        </select>
        <p v-if="config.p" class="form-hint" style="color: var(--ios-orange);">
          ⚠️ {{ t('customIPDisabledHint') || '使用自定义ProxyIP时，地区选择已禁用' }}
        </p>
      </div>

      <!-- Protocol Selection -->
      <div class="form-group">
        <label class="form-label">{{ t('protocolSelection') }}</label>
        <div class="protocol-section">
          <div class="checkbox-group">
            <div class="checkbox-item">
              <input type="checkbox" id="ev" v-model="config.ev" true-value="yes" false-value="no">
              <label for="ev">{{ t('enableVLESS') }}</label>
            </div>
            <div class="checkbox-item">
              <input type="checkbox" id="et" v-model="config.et" true-value="yes" false-value="no">
              <label for="et">{{ t('enableTrojan') }}</label>
            </div>
            <div class="checkbox-item">
              <input type="checkbox" id="ex" v-model="config.ex" true-value="yes" false-value="no">
              <label for="ex">{{ t('enableXhttp') }}</label>
            </div>
          </div>
        </div>
      </div>

      <!-- ECH Settings -->
      <div class="divider"></div>
      <h3 class="section-title">{{ t('echSettings') }}</h3>
      
      <div class="toggle-with-hint">
        <div class="toggle-row">
          <span class="toggle-label">{{ t('enableECH') }}</span>
          <label class="toggle-switch">
            <input type="checkbox" v-model="config.ech" true-value="yes" false-value="no">
            <span class="toggle-slider"></span>
          </label>
        </div>
        <p class="toggle-hint">{{ t('enableECHHint') }}</p>
      </div>

      <div class="form-group" v-if="config.ech === 'yes'">
        <label class="form-label">{{ t('customDNS') }}</label>
        <input 
          type="text" 
          v-model="config.customDNS" 
          class="ios-input" 
          :placeholder="t('customDNSPlaceholder')"
        >
      </div>

      <div class="form-group" v-if="config.ech === 'yes'">
        <label class="form-label">{{ t('customECHDomain') }}</label>
        <input 
          type="text" 
          v-model="config.customECHDomain" 
          class="ios-input" 
          :placeholder="t('customECHDomainPlaceholder')"
        >
      </div>

      <!-- Trojan Password -->
      <div class="form-group">
        <label class="form-label">{{ t('trojanPassword') }}</label>
        <input 
          type="text" 
          v-model="config.tp" 
          class="ios-input" 
          :placeholder="t('trojanPasswordPlaceholder')"
        >
      </div>

      <!-- Custom Path -->
      <div class="form-group">
        <label class="form-label">{{ t('customPath') }}</label>
        <input 
          type="text" 
          v-model="config.d" 
          class="ios-input" 
          :placeholder="t('customPathPlaceholder')"
        >
      </div>

      <!-- Custom IP -->
      <div class="form-group">
        <label class="form-label">{{ t('customIP') }}</label>
        <input 
          type="text" 
          v-model="config.p" 
          class="ios-input" 
          :placeholder="t('customIPPlaceholder')"
        >
      </div>

      <!-- Preferred IPs -->
      <div class="form-group">
        <label class="form-label">{{ t('preferredIPs') }}</label>
        <textarea 
          v-model="config.yx" 
          class="ios-input" 
          rows="3"
          :placeholder="t('preferredIPsPlaceholder')"
          style="resize: vertical;"
        ></textarea>
      </div>

      <!-- Preferred IPs URL -->
      <div class="form-group">
        <label class="form-label">{{ t('preferredIPsURL') }}</label>
        <input 
          type="text" 
          v-model="config.yxURL" 
          class="ios-input" 
          :placeholder="t('preferredIPsURLPlaceholder')"
        >
      </div>

      <!-- Latency Test Section -->
      <div class="latency-section">
        <div class="latency-header">
          <span class="latency-icon">⚡</span>
          <span class="latency-title">{{ t('latencyTest') }}</span>
        </div>
        
        <div class="latency-controls">
          <div class="latency-input-group" style="flex: 2;">
            <label>{{ t('latencyTestIP') }}</label>
            <input 
              type="text" 
              v-model="latencyInput" 
              class="latency-input" 
              :placeholder="t('latencyTestIPPlaceholder')"
            >
          </div>
          <div class="latency-input-group" style="flex: 0.5;">
            <label>{{ t('latencyTestPort') }}</label>
            <input 
              type="number" 
              v-model="latencyPort" 
              class="latency-input" 
              value="443"
            >
          </div>
        </div>

        <div class="latency-buttons">
          <button class="ios-btn ios-btn-primary" @click="startLatencyTest" :disabled="testing">
            {{ testing ? '...' : t('startTest') }}
          </button>
          <button class="ios-btn ios-btn-secondary" @click="stopLatencyTest" v-if="testing">
            {{ t('stopTest') }}
          </button>
        </div>

        <!-- Test Results -->
        <div v-if="latencyResults.length > 0" class="latency-results">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <span style="font-size: 13px; color: var(--ios-text-secondary);">
              {{ t('testResult') }} ({{ selectedResults.length }}/{{ latencyResults.length }})
            </span>
            <div style="display: flex; gap: 8px;">
              <button class="ios-btn ios-btn-secondary" style="padding: 6px 12px; font-size: 12px;" @click="selectAll">
                {{ t('selectAll') }}
              </button>
              <button class="ios-btn ios-btn-secondary" style="padding: 6px 12px; font-size: 12px;" @click="deselectAll">
                {{ t('deselectAll') }}
              </button>
            </div>
          </div>
          
          <div 
            v-for="(result, idx) in latencyResults" 
            :key="idx"
            class="latency-result-item"
            :style="{ opacity: result.selected ? 1 : 0.5 }"
          >
            <input 
              type="checkbox" 
              v-model="result.selected"
            >
            <div class="latency-result-info">
              <span class="latency-result-ip">{{ result.host }}:{{ result.port }}</span>
              <span class="latency-result-latency">{{ result.latency }}ms</span>
            </div>
          </div>

          <div class="latency-actions">
            <button class="ios-btn ios-btn-success" @click="overwriteToYx">
              {{ t('overwrite') || '覆盖添加' }}
            </button>
            <button class="ios-btn ios-btn-primary" @click="appendToYx">
              {{ t('append') || '追加添加' }}
            </button>
          </div>
        </div>
      </div>

      <!-- Advanced Controls -->
      <div class="divider"></div>
      <h3 class="section-title">{{ t('subscriptionConverter') }}</h3>

      <div class="form-group">
        <input 
          type="text" 
          v-model="config.scu" 
          class="ios-input" 
          :placeholder="t('subscriptionConverterPlaceholder')"
        >
      </div>

      <!-- API Management -->
      <div class="toggle-with-hint">
        <div class="toggle-row">
          <span class="toggle-label">{{ t('apiManagement') }}</span>
          <label class="toggle-switch">
            <input type="checkbox" v-model="config.ae" true-value="yes" false-value="">
            <span class="toggle-slider"></span>
          </label>
        </div>
        <p class="toggle-hint">{{ t('apiEnabledHint') }}</p>
      </div>

      <!-- Downgrade Mode -->
      <div class="toggle-with-hint">
        <div class="toggle-row">
          <span class="toggle-label">{{ t('downgradeMode') }}</span>
          <label class="toggle-switch">
            <input type="checkbox" v-model="config.qj" true-value="no" false-value="">
            <span class="toggle-slider"></span>
          </label>
        </div>
        <p class="toggle-hint">{{ t('downgradeModeHint') }}</p>
      </div>

      <!-- TLS Only -->
      <div class="toggle-with-hint">
        <div class="toggle-row">
          <span class="toggle-label">{{ t('tlsOnly') }}</span>
          <label class="toggle-switch">
            <input type="checkbox" v-model="config.dkby" true-value="yes" false-value="">
            <span class="toggle-slider"></span>
          </label>
        </div>
        <p class="toggle-hint">{{ t('tlsOnlyHint') }}</p>
      </div>

      <!-- Builtin Preferred -->
      <div class="toggle-with-hint">
        <div class="toggle-row">
          <span class="toggle-label">{{ t('builtinPreferred') }}</span>
          <label class="toggle-switch">
            <input type="checkbox" v-model="config.yxby" true-value="yes" false-value="">
            <span class="toggle-slider"></span>
          </label>
        </div>
      </div>
    </div>

    <!-- Bottom Action Bar -->
    <div class="action-bar">
      <button class="ios-btn ios-btn-primary" @click="saveConfig">
        {{ t('saveAll') }}
      </button>
      <button class="ios-btn ios-btn-secondary" @click="refreshConfig">
        ↻
      </button>
      <button class="ios-btn ios-btn-danger" @click="resetConfig">
        ⌫
      </button>
    </div>

    <!-- Toast -->
    <div v-if="toast.show" class="toast" :class="toast.type">
      {{ toast.message }}
    </div>
  </div>
</template>

<script setup>
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'

const { t, locale } = useI18n()

const isRtl = computed(() => locale.value === 'fa')

// Clients
const clients = [
  { id: 'clash', name: 'Clash', base64: 'Y2xhc2g=' },
  { id: 'stash', name: 'Stash', base64: 'Y2xhc2g=' },
  { id: 'surge', name: 'Surge', base64: 'c3VyZ2U=' },
  { id: 'singbox', name: 'sing-box', base64: 'c2luZ2JveA==' },
  { id: 'loon', name: 'Loon', base64: 'bG9vbg==' },
  { id: 'quantumultx', name: 'Quantumult X', base64: 'cXVhbng=' },
  { id: 'v2ray', name: 'V2Ray', base64: 'djJyYXk=' },
  { id: 'v2rayng', name: 'V2RayNG', base64: 'djJyYXk=' },
  { id: 'nekoray', name: 'NekoRay', base64: 'djJyYXk=' },
  { id: 'shadowrocket', name: 'Shadowrocket', base64: 'djJyYXk=' }
]

// Region names with flags
const regionNames = {
  HK: '🇭🇰 香港',
  US: '🇺🇸 美国',
  SG: '🇸🇬 新加坡',
  JP: '🇯🇵 日本',
  KR: '🇰🇷 韩国',
  DE: '🇩🇪 德国',
  SE: '🇸🇪 瑞典',
  NL: '🇳🇱 荷兰',
  FI: '🇫🇮 芬兰',
  GB: '🇬🇧 英国',
  AU: '🇦🇺 澳洲',
  BR: '🇧🇷 巴西',
  CA: '🇨🇦 加拿大',
  FR: '🇫🇷 法国',
  CH: '🇨🇭 瑞士',
  RU: '🇷🇺 俄罗斯',
  IN: '🇮🇳 印度',
  TW: '🇹🇼 台湾',
  Oracle: '🟠 Oracle',
  DigitalOcean: '🔵 DigitalOcean',
  Vultr: '🟣 Vultr',
  Multacom: '⚫ Multacom'
}

// State
const selectedClient = ref('')
const subscriptionUrl = ref('')
const userUuid = ref(localStorage.getItem('cfnew_uuid') || '')
const regionStatus = ref('🇺🇸 美国')
const detectionMethod = ref('Cloudflare内置检测')
const echStatus = ref('检测中...')
const echStatusClass = ref('')
const kvStatus = ref('')
const kvStatusClass = ref('')
const testing = ref(false)
const latencyInput = ref('')
const latencyPort = ref(443)
const latencyResults = ref([])
const toast = reactive({ show: false, message: '', type: '' })

const config = reactive({
  wk: '',
  ev: 'yes',
  et: 'no',
  ex: 'no',
  ech: 'no',
  tp: '',
  customDNS: '',
  customECHDomain: '',
  d: '',
  p: '',
  yx: '',
  yxURL: '',
  s: '',
  homepage: '',
  scu: '',
  ena: 'no',
  epd: 'yes',
  epi: 'yes',
  egi: 'yes',
  ae: '',
  rm: '',
  qj: '',
  dkby: '',
  yxby: '',
  ipv4: 'yes',
  ipv6: 'yes',
  ispMobile: 'yes',
  ispUnicom: 'yes',
  ispTelecom: 'yes'
})

// Methods
function setLocale(lang) {
  locale.value = lang
  localStorage.setItem('preferredLanguage', lang)
  const expiryDate = new Date()
  expiryDate.setFullYear(expiryDate.getFullYear() + 1)
  document.cookie = `preferredLanguage=${lang}; path=/; expires=${expiryDate.toUTCString()}; SameSite=Lax`
}

function onUuidChange() {
  localStorage.setItem('cfnew_uuid', userUuid.value)
  updateSubscriptionUrl()
}


function getApiUrl(path) {
  const base = import.meta.env.VITE_WORKER_URL || ''
  if (!userUuid.value) return base + path
  return base + '/' + userUuid.value + path
}

function updateSubscriptionUrl() {
  if (!userUuid.value) {
    subscriptionUrl.value = ''
    return
  }
  const base = import.meta.env.VITE_WORKER_URL || ''
  subscriptionUrl.value = base + '/' + userUuid.value + '/sub'
}

function statusClass(status) {
  if (status.includes('检测') || status.includes('در حال')) return ''
  if (status.includes('失败') || status.includes('ناموفق')) return 'error'
  return 'success'
}

function selectClient(client) {
  selectedClient.value = client.id
  generateClientLink(client)
}

function generateClientLink(client) {
  const currentUrl = window.location.href
  subscriptionUrl.value = import.meta.env.getApiUrl('/sub')
  
  // Try to open app or copy to clipboard
  const schemeUrl = getSchemeUrl(client)
  if (schemeUrl) {
    tryOpenApp(schemeUrl, () => {
      copyToClipboard(subscriptionUrl.value)
    })
  } else {
    copyToClipboard(subscriptionUrl.value)
  }
}

function getSchemeUrl(client) {
  switch (client.id) {
    case 'shadowrocket':
      return `shadowrocket://add/${encodeURIComponent(subscriptionUrl.value)}`
    case 'v2rayng':
      return `v2rayng://install?url=${encodeURIComponent(subscriptionUrl.value)}`
    case 'nekoray':
      return `nekoray://install-config?url=${encodeURIComponent(subscriptionUrl.value)}`
    case 'stash':
      return `stash://install?url=${encodeURIComponent(subscriptionUrl.value)}`
    case 'clash':
      return `clash://install-config?url=${encodeURIComponent(subscriptionUrl.value)}`
    case 'surge':
      return `surge:///install-config?url=${encodeURIComponent(subscriptionUrl.value)}`
    case 'singbox':
      return `sing-box://install-config?url=${encodeURIComponent(subscriptionUrl.value)}`
    case 'loon':
      return `loon://install?url=${encodeURIComponent(subscriptionUrl.value)}`
    case 'quantumultx':
      return `quantumult-x://install-config?url=${encodeURIComponent(subscriptionUrl.value)}`
    default:
      return null
  }
}

function tryOpenApp(schemeUrl, fallback) {
  const startTime = Date.now()
  const iframe = document.createElement('iframe')
  iframe.style.display = 'none'
  iframe.src = schemeUrl
  document.body.appendChild(iframe)
  
  setTimeout(() => {
    iframe.parentNode?.removeChild(iframe)
    const elapsed = Date.now() - startTime
    if (elapsed > 2500) {
      fallback?.()
    }
  }, 2000)
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text)
    showToast(t('copySuccess'), 'success')
  } catch (err) {
    showToast(t('copyFailed'), 'error')
  }
}

function showToast(message, type = '') {
  toast.message = message
  toast.type = type
  toast.show = true
  setTimeout(() => {
    toast.show = false
  }, 2500)
}

async function checkSystemStatus() {
  try {
    const response = await fetch(import.meta.env.getApiUrl('/region'))
    const data = await response.json()
    
    if (data.region === 'CUSTOM') {
      regionStatus.value = '🔧 ' + t('customIPMode')
      detectionMethod.value = t('customIPMode')
    } else if (data.region && regionNames[data.region]) {
      regionStatus.value = regionNames[data.region]
      detectionMethod.value = data.detectionMethod || t('cloudflareDetection')
    }
  } catch (e) {
    regionStatus.value = '❌ ' + t('detectionFailed')
    detectionMethod.value = '❌ ' + t('detectionFailed')
  }
}

async function checkKVStatus() {
  try {
    const response = await fetch(import.meta.env.getApiUrl('/api/config'))
    
    if (response.status === 503) {
      kvStatus.value = t('kvNotEnabled')
      kvStatusClass.value = 'warning'
    } else if (response.ok) {
      const data = await response.json()
      if (data.kvEnabled) {
        kvStatus.value = t('kvStatusOK')
        kvStatusClass.value = 'ok'
        await loadConfig()
      } else {
        kvStatus.value = t('kvNotEnabled')
        kvStatusClass.value = 'warning'
      }
    }
  } catch (e) {
    kvStatus.value = t('kvStatusError')
    kvStatusClass.value = 'error'
  }
}

async function checkECHStatus() {
  try {
    const subUrl = import.meta.env.getApiUrl('/sub')
    const response = await fetch(subUrl, {
      method: 'GET',
      headers: { 'Accept': 'text/plain' }
    })
    
    const echHeader = response.headers.get('X-ECH-Status')
    if (echHeader === 'ENABLED') {
      echStatus.value = t('echEnabled')
      echStatusClass.value = 'success'
    } else {
      echStatus.value = t('echDisabled')
      echStatusClass.value = 'warning'
    }
  } catch (e) {
    echStatus.value = t('echCheckFailed')
    echStatusClass.value = 'error'
  }
}

async function loadConfig() {
  try {
    const response = await fetch(import.meta.env.getApiUrl('/api/config'))
    if (!response.ok) return
    
    const data = await response.json()
    
    // Load config into reactive state
    Object.keys(data).forEach(key => {
      if (key in config) {
        config[key] = data[key] || ''
      }
    })
  } catch (e) {
    console.error('Failed to load config:', e)
  }
}

async function saveConfig() {
  // Validate at least one protocol is enabled
  if (config.ev !== 'yes' && config.et !== 'yes' && config.ex !== 'yes') {
    showToast(t('atLeastOneProtocol'), 'error')
    return
  }

  try {
    const response = await fetch(import.meta.env.getApiUrl('/api/config'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config)
    })

    if (response.ok) {
      showToast(t('saveSuccess'), 'success')
      setTimeout(() => {
        window.location.reload()
      }, 1500)
    } else {
      showToast(t('copyFailed'), 'error')
    }
  } catch (e) {
    showToast(t('copyFailed'), 'error')
  }
}

async function resetConfig() {
  if (!confirm(locale.value === 'fa' ? 'آیا مطمئن هستید؟' : '确定要重置所有配置吗？')) {
    return
  }

  try {
    const response = await fetch(import.meta.env.getApiUrl('/api/config'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        wk: '', d: '', p: '', yx: '', yxURL: '', s: '', ae: '',
        rm: '', qj: '', dkby: '', yxby: '', ev: '', et: '', ex: '', 
        tp: '', scu: '', epd: '', epi: '', egi: '',
        ipv4: '', ipv6: '', ispMobile: '', ispUnicom: '', ispTelecom: '',
        homepage: ''
      })
    })

    if (response.ok) {
      showToast(t('resetSuccess'), 'success')
      setTimeout(() => {
        window.location.reload()
      }, 1500)
    }
  } catch (e) {
    showToast(t('copyFailed'), 'error')
  }
}

function refreshConfig() {
  loadConfig()
  showToast(t('saved') || '已刷新', '')
}

// Latency Test
let testAbortController = null

async function startLatencyTest() {
  if (!latencyInput.value.trim()) {
    showToast(t('inputIP'), 'error')
    return
  }

  testing.value = true
  latencyResults.value = []
  
  const targets = latencyInput.value.split(',').map(t => t.trim()).filter(t => t)
  const port = latencyPort.value || 443
  
  testAbortController = new AbortController()
  
  for (const target of targets) {
    if (testAbortController.signal.aborted) break
    
    const { host, port: p } = parseTarget(target, port)
    const result = await testLatency(host, p)
    result.selected = true
    
    if (result.success) {
      latencyResults.value.push(result)
    }
  }
  
  testing.value = false
}

function stopLatencyTest() {
  if (testAbortController) {
    testAbortController.abort()
  }
  testing.value = false
  showToast(t('testStopped'), '')
}

function parseTarget(target, defaultPort) {
  let host = target
  let port = defaultPort
  
  if (target.includes('#')) {
    const parts = target.split('#')
    host = parts[0]
  }
  
  if (host.includes(':') && !host.startsWith('[')) {
    const lastColon = host.lastIndexOf(':')
    const possiblePort = host.substring(lastColon + 1)
    if (/^[0-9]+$/.test(possiblePort)) {
      port = parseInt(possiblePort)
      host = host.substring(0, lastColon)
    }
  }
  
  return { host, port }
}

async function testLatency(host, port) {
  const timeout = 8000
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), timeout)
  
  try {
    const cleanHost = host.replace(/^\[|\]$/g, '')
    const hexIP = ipToHex(cleanHost)
    const testDomain = hexIP ? `${hexIP}.nip.lfree.org` : `${cleanHost}.nip.lfree.org`
    const testUrl = `https://${testDomain}:${port}/`
    
    const start = Date.now()
    const response = await fetch(testUrl, { signal: controller.signal })
    await response.text()
    const latency = Date.now() - start
    
    clearTimeout(timeoutId)
    
    return {
      success: response.ok,
      host,
      port,
      latency,
      colo: ''
    }
  } catch (error) {
    clearTimeout(timeoutId)
    return {
      success: false,
      host,
      port,
      latency: -1,
      error: error.name === 'AbortError' ? 'timeout' : error.message
    }
  }
}

function ipToHex(ip) {
  const parts = ip.split('.')
  if (parts.length !== 4) return null
  
  let hex = ''
  for (const num of parts) {
    const n = parseInt(num)
    if (isNaN(n) || n < 0 || n > 255) return null
    hex += n.toString(16).padStart(2, '0')
  }
  return hex
}

const selectedResults = computed(() => latencyResults.value.filter(r => r.selected))

function selectAll() {
  latencyResults.value.forEach(r => r.selected = true)
}

function deselectAll() {
  latencyResults.value.forEach(r => r.selected = false)
}

async function overwriteToYx() {
  const items = selectedResults.value
  if (items.length === 0) {
    showToast(t('selectResults'), 'error')
    return
  }
  
  config.yx = items.map(r => `${r.host}:${r.port}#${r.host}`).join(',')
  await saveConfig()
  showToast(`${items.length} ${t('items')} ${t('savedAnd')}`, 'success')
}

async function appendToYx() {
  const items = selectedResults.value
  if (items.length === 0) {
    showToast(t('selectResults'), 'error')
    return
  }
  
  const newItems = items.map(r => `${r.host}:${r.port}#${r.host}`).join(',')
  config.yx = config.yx ? `${config.yx},${newItems}` : newItems
  await saveConfig()
  showToast(`${items.length} ${t('items')} ${t('savedAnd')}`, 'success')
}

// Watch for ECH toggle to auto-enable TLS
watch(() => config.ech, (newVal) => {
  if (newVal === 'yes') {
    config.dkby = 'yes'
  }
})

// Watch for custom IP to disable region selection
watch(() => config.p, (newVal) => {
  if (newVal && newVal.trim()) {
    config.wk = ''
  }
})

// On mount
onMounted(async () => {
  await checkSystemStatus()
  await checkKVStatus()
  await checkECHStatus()
})
</script>
