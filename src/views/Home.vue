<template>
    <div class="home-container" :class="{ 'dark-mode': isDarkMode }">
        <div class="header">
            <h2>域名管理系统(Domains-Support)</h2>
            <div class="header-buttons">
                <el-dropdown trigger="click">
                    <el-button type="primary" size="small" :icon="Refresh" :loading="refreshLoading">
                        刷新
                        <el-icon class="el-icon--right"><arrow-down /></el-icon>
                    </el-button>
                    <template #dropdown>
                        <el-dropdown-menu>
                            <el-dropdown-item @click="handleRefreshTable">刷新页面</el-dropdown-item>
                            <el-dropdown-item @click="handleRefreshStatus">检查域名状态</el-dropdown-item>
                        </el-dropdown-menu>
                    </template>
                </el-dropdown>
                <el-dropdown trigger="click">
                    <el-button type="primary" size="small">
                        系统
                        <el-icon class="el-icon--right"><arrow-down /></el-icon>
                    </el-button>
                    <template #dropdown>
                        <el-dropdown-menu>
                            <el-dropdown-item @click="handleAdd">
                                <el-icon>
                                    <Plus />
                                </el-icon>新增
                            </el-dropdown-item>
                            <el-dropdown-item @click="handleCopyAdd">
                                <el-icon>
                                    <CopyDocument />
                                </el-icon>复制新增
                            </el-dropdown-item>
                            <el-dropdown-item @click="handleCopyInfo">
                                <el-icon>
                                    <CopyDocument />
                                </el-icon>{{ copyInfoLabel }}
                            </el-dropdown-item>
                            <el-dropdown-item @click="handleConfig">
                                <el-icon>
                                    <Setting />
                                </el-icon>配置
                            </el-dropdown-item>
                            <el-dropdown-item @click="handleImport">
                                <el-icon>
                                    <Upload />
                                </el-icon>导入
                            </el-dropdown-item>
                            <el-dropdown-item @click="handleExport">
                                <el-icon>
                                    <Download />
                                </el-icon>导出
                            </el-dropdown-item>
                        </el-dropdown-menu>
                    </template>
                </el-dropdown>
                <el-tooltip content="登出系统" placement="bottom">
                    <el-button type="primary" size="small" :icon="SwitchButton" @click="handleLogout">登出</el-button>
                </el-tooltip>
                <el-switch v-model="isDarkMode" :active-icon="Moon" :inactive-icon="Sunny" @change="toggleDarkMode"
                    inline-prompt class="theme-switch" style="--el-switch-on-color: #409EFF; --el-switch-off-color: #4c4d4f; --el-switch-border-color: #4c4d4f;" />
            </div>
        </div>

        <div class="table-operations">
            <el-button type="danger" :icon="Delete" @click="handleBatchDelete" v-if="selectedRows.length > 0" class="batch-delete-btn">
                批量删除 ({{ selectedRows.length }})
            </el-button>
            <el-input v-model="searchQuery" placeholder="搜索域名、域名商或备注..." :prefix-icon="Search" clearable
                class="search-input" />
        </div>

        <el-table ref="domainTableRef" :data="paginatedDomains" border style="width: 100%" class="custom-table" @selection-change="handleSelectionChange">
            <el-table-column type="selection" width="55" align="center" :selectable="isRowSelectable" />
            <el-table-column type="index" label="序号" width="60" align="center">
                <template #default="scope">
                    {{ (currentPage - 1) * pageSize + scope.$index + 1 }}
                </template>
            </el-table-column>
            <el-table-column label="域名" align="center" sortable prop="domain">
                <template #default="scope">
                    <a :href="'https://' + scope.row.domain" target="_blank" class="link"
                        v-html="highlightText(scope.row.domain)"></a>
                </template>
            </el-table-column>
            <el-table-column label="域名商" align="center" sortable prop="registrar">
                <template #default="scope">
                    <a :href="scope.row.registrar_link" target="_blank" class="link"
                        v-html="highlightText(scope.row.registrar)"></a>
                </template>
            </el-table-column>
            <el-table-column prop="registrar_date" label="注册时间" align="center" sortable />
            <el-table-column prop="expiry_date" label="过期时间" align="center" sortable>
                <template #default="scope">
                    <span>{{ formatExpiryDate(scope.row.expiry_date) }}</span>
                </template>
            </el-table-column>
            <el-table-column label="剩余时间" align="center" sortable
                :sort-method="(a, b) => calculateRemainingDays(a.expiry_date) - calculateRemainingDays(b.expiry_date)">
                <template #default="scope">
                    <span v-if="isPermanentExpiry(scope.row.expiry_date)">永久</span>
                    <span v-else :class="{ 'warning-text': calculateRemainingDays(scope.row.expiry_date) <= alertDays }">
                        {{ calculateRemainingDays(scope.row.expiry_date) }}天
                    </span>
                </template>
            </el-table-column>
            <el-table-column prop="service_type" label="服务类型" align="center" sortable />
            <el-table-column prop="cert_status" label="证书状态" align="center" sortable>
                <template #default="scope">
                    <span :class="{
                        'success-text': scope.row.cert_status === '成功',
                        'warning-text': scope.row.cert_status === '申请中',
                        'danger-text': scope.row.cert_status === '失败'
                    }">
                        {{ scope.row.cert_status || '无' }}
                    </span>
                </template>
            </el-table-column>
            <el-table-column prop="status" label="状态" align="center" sortable>
                <template #default="scope">
                    <span :class="scope.row.status === '在线' ? 'success-text' : 'danger-text'">
                        {{ scope.row.status }}
                    </span>
                </template>
            </el-table-column>
            <el-table-column prop="memo" label="备注" align="center" sortable>
                <template #default="scope">
                    <span v-html="highlightText(scope.row.memo)"></span>
                </template>
            </el-table-column>
            <el-table-column label="操作" width="200" align="center">
                <template #default="scope">
                    <el-button type="primary" size="small" :icon="Edit" @click="handleEdit(scope.row)">修改</el-button>
                    <el-button type="danger" size="small" :icon="Delete" @click="handleDelete(scope.row)">删除</el-button>
                </template>
            </el-table-column>
        </el-table>

        <div class="pagination-container">
            <el-pagination v-model:current-page="currentPage" v-model:page-size="pageSize"
                :page-sizes="[20, 50, 100, 200]" :background="true" layout="total, sizes, prev, pager, next, jumper"
                :total="filteredDomains.length" @size-change="handleSizeChange" @current-change="handleCurrentChange" />
        </div>

        <DomainDialog v-model:visible="dialogVisible" :is-edit="isEdit" :edit-data="editData"
            :websites="websiteConfigs" :server-ip="serverIp" @submit="handleDialogSubmit" />

        <AlertConfigDialog v-model:visible="configVisible" :config="alertConfig" @submit="handleConfigSubmit"
            @websites-updated="loadWebsiteConfigs" />

        <ImportDialog v-model:visible="importVisible" @success="loadDomains" />

        <footer class="footer">
            <div class="footer-content">
                <div class="copyright">
                    <span>© 2025 Domains-Support v1.2.0</span>
                    <span class="separator">|</span>
                    <span>作者：饭奇骏</span>
                    <span class="separator">|</span>
                    <div class="social-links">
                        <a href="https://github.com/frankiejun/Domains-Support/tree/main" target="_blank"
                            class="social-link" title="访问 GitHub 仓库">
                            <el-icon class="social-icon"><svg viewBox="0 0 1024 1024" width="20" height="20">
                                    <path fill="currentColor"
                                        d="M512 0C229.12 0 0 229.12 0 512c0 226.56 146.56 417.92 350.08 485.76 25.6 4.48 35.2-10.88 35.2-24.32 0-12.16-0.64-52.48-0.64-95.36-128.64 23.68-161.92-31.36-172.16-60.16-5.76-14.72-30.72-60.16-52.48-72.32-17.92-9.6-43.52-33.28-0.64-33.92 40.32-0.64 69.12 37.12 78.72 52.48 46.08 77.44 119.68 55.68 149.12 42.24 4.48-33.28 17.92-55.68 32.64-68.48-113.92-12.8-232.96-56.96-232.96-252.8 0-55.68 19.84-101.76 52.48-137.6-5.12-12.8-23.04-65.28 5.12-135.68 0 0 42.88-13.44 140.8 52.48 40.96-11.52 84.48-17.28 128-17.28 43.52 0 87.04 5.76 128 17.28 97.92-66.56 140.8-52.48 140.8-52.48 28.16 70.4 10.24 122.88 5.12 135.68 32.64 35.84 52.48 81.28 52.48 137.6 0 196.48-119.68 240-233.6 252.8 18.56 16 34.56 46.72 34.56 94.72 0 68.48-0.64 123.52-0.64 140.8 0 13.44 9.6 29.44 35.2 24.32C877.44 929.92 1024 737.92 1024 512 1024 229.12 794.88 0 512 0z" />
                                </svg></el-icon>
                        </a>
                        <a href="https://www.youtube.com/@frankiejun8965" target="_blank" class="social-link"
                            title="访问 YouTube 频道">
                            <el-icon class="social-icon"><svg viewBox="0 0 1024 1024" width="20" height="20">
                                    <path fill="currentColor"
                                        d="M941.3 296.1c-10.3-38.6-40.7-69-79.3-79.3C792.2 198 512 198 512 198s-280.2 0-350 18.7c-38.6 10.3-69 40.7-79.3 79.3C64 365.9 64 512 64 512s0 146.1 18.7 215.9c10.3 38.6 40.7 69 79.3 79.3C231.8 826 512 826 512 826s280.2 0 350-18.7c38.6-10.3 69-40.7 79.3-79.3C960 658.1 960 512 960 512s0-146.1-18.7-215.9zM423 646V378l232 134-232 134z" />
                                </svg></el-icon>
                        </a>
                    </div>
                </div>
            </div>
        </footer>
    </div>
</template>

<script setup lang="ts">
import { ArrowDown, CopyDocument, Delete, Download, Edit, Moon, Plus, Refresh, Search, Setting, Sunny, SwitchButton, Upload } from '@element-plus/icons-vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { createDomain, deleteDomain, updateDomain, type DomainData } from '../api/domains'
import AlertConfigDialog from '../components/AlertConfigDialog.vue'
import DomainDialog from '../components/DomainDialog.vue'
import ImportDialog from '../components/ImportDialog.vue'
import { useAuth } from '../utils/auth'

type Domain = DomainData

interface AlertConfig {
    tg_token: string
    tg_userid: string
    wx_api: string
    wx_token: string
    days: number
    auto_check_enabled: number
    auto_check_interval: number
}

interface WebsiteConfig {
    id: number
    name: string
    filename: string
}
interface ApiResponse<T = any> {
    status: number
    message: string
    data: T
}

const router = useRouter()
const auth = useAuth()
const domains = ref<Domain[]>([])
const alertDays = ref(30)
const alertConfig = ref<AlertConfig>()
const websiteConfigs = ref<WebsiteConfig[]>([])
const serverIp = ref('')
const refreshingTable = ref(false)
const refreshingStatus = ref(false)
const refreshLoading = computed(() => refreshingTable.value || refreshingStatus.value)
const permanentExpiryDate = '2099-12-31'
let certStatusSource: EventSource | null = null
let certStatusReconnectTimer: number | null = null
let certStatusRefreshTimer: number | null = null

// 搜索和分页状态
const searchQuery = ref('')
const currentPage = ref(1)
const pageSize = ref(20)

// 过滤后的域名列表
const filteredDomains = computed(() => {
    if (!searchQuery.value) return domains.value
    const query = searchQuery.value.toLowerCase()
    return domains.value.filter((domain: Domain) => 
        domain.domain.toLowerCase().includes(query) ||
        domain.registrar?.toLowerCase().includes(query) ||
        domain.memo?.toLowerCase().includes(query)
    )
})

// 分页后的域名列表
const paginatedDomains = computed(() => {
    const start = (currentPage.value - 1) * pageSize.value
    const end = start + pageSize.value
    return filteredDomains.value.slice(start, end)
})

// 高亮匹配文本
const highlightText = (text: string | undefined) => {
    if (!text) return ''
    if (!searchQuery.value) return text
    const query = searchQuery.value
    const regex = new RegExp(`(${query})`, 'gi')
    return text.replace(regex, '<span class="highlight">$1</span>')
}

const handleSizeChange = (val: number) => {
    pageSize.value = val
    currentPage.value = 1
}

const handleCurrentChange = (val: number) => {
    currentPage.value = val
}

const isPermanentExpiry = (expiryDate: string) => expiryDate === permanentExpiryDate

const formatExpiryDate = (expiryDate: string) => {
    if (isPermanentExpiry(expiryDate)) return '永久'
    return expiryDate
}

// 对话框相关的状态
const dialogVisible = ref(false)
const configVisible = ref(false)
const isEdit = ref(false)
const editData = ref<Domain>()
const importVisible = ref(false)
const domainTableRef = ref()
const copyMode = ref(false)
const copySource = ref<Domain>()
const copyInfoLabel = computed(() => (copyMode.value ? '确认复制' : '复制信息'))

// 暗黑模式状态
const isDarkMode = ref(localStorage.getItem('darkMode') === 'true')

const checkLoginStatus = () => {
    const token = auth.getAuthToken()
    if (!token) {
        router.push({ name: 'Login' })
    }
}

const handleLogout = () => {
    auth.clearAuth()
    router.push({ name: 'Login' })
}

const handleAdd = () => {
    isEdit.value = false
    editData.value = undefined
    dialogVisible.value = true
}

const handleCopyAdd = () => {
    if (selectedRows.value.length === 0) {
        ElMessage.warning('请先选择一条记录')
        return
    }
    if (selectedRows.value.length > 1) {
        ElMessage.warning('只能选择一条记录进行复制新增')
        return
    }

    const row = selectedRows.value[0]
    isEdit.value = false
    editData.value = {
        domain: row.domain,
        registrar: row.registrar,
        registrar_link: row.registrar_link,
        registrar_date: row.registrar_date,
        expiry_date: row.expiry_date,
        service_type: row.service_type,
        status: row.status,
        tgsend: row.tgsend,
        st_tgsend: row.st_tgsend,
        site_id: row.site_id,
        memo: row.memo
    }
    dialogVisible.value = true
}

const handleCopyInfo = () => {
    if (!copyMode.value) {
        if (selectedRows.value.length === 0) {
            ElMessage.warning('请先选择一条记录')
            return
        }
        if (selectedRows.value.length > 1) {
            ElMessage.warning('只能选择一条记录作为复制来源')
            return
        }

        copySource.value = selectedRows.value[0]
        copyMode.value = true
        selectedRows.value = []
        domainTableRef.value?.clearSelection()
        ElMessage.info('已选择复制来源，请在表格中选择目标记录后再次点击复制信息')
        return
    }

    const source = copySource.value
    if (!source) {
        copyMode.value = false
        return
    }

    const targets = selectedRows.value.filter((item: Domain) => item.id !== source.id)
    if (targets.length === 0) {
        ElMessage.warning('请选择需要修改信息的记录')
        return
    }

    ElMessageBox.confirm(`确定将 ${source.domain} 的信息复制到选中的 ${targets.length} 条记录吗？`, '复制信息确认', {
        type: 'warning'
    }).then(async () => {
        const loading = ElMessage.info({
            message: '正在复制信息...',
            duration: 0
        })

        let successCount = 0
        let failCount = 0

        const updatePromises = targets.map(async (target: Domain) => {
            if (!target.id) {
                failCount++
                return
            }

            const updateData = {
                domain: target.domain,
                registrar: source.registrar,
                registrar_link: source.registrar_link,
                registrar_date: source.registrar_date,
                expiry_date: source.expiry_date,
                service_type: source.service_type,
                status: source.status,
                tgsend: source.tgsend,
                st_tgsend: source.st_tgsend,
                site_id: source.site_id,
                memo: source.memo
            }

            try {
                await updateDomain(target.id, updateData)
                successCount++
            } catch (error) {
                failCount++
            }
        })

        await Promise.all(updatePromises)
        loading.close()

        if (failCount === 0) {
            ElMessage.success(`成功复制到 ${successCount} 条记录`)
        } else {
            ElMessage.warning(`复制完成: 成功 ${successCount} 条, 失败 ${failCount} 条`)
        }

        copyMode.value = false
        copySource.value = undefined
        selectedRows.value = []
        domainTableRef.value?.clearSelection()
        await loadDomains()
    }).catch(() => {})
}

const handleEdit = (row: Domain) => {
    isEdit.value = true
    editData.value = row
    dialogVisible.value = true
}

const handleDelete = async (row: Domain) => {
    try {
        await ElMessageBox.confirm('确定要删除该域名吗？', '提示', {
            type: 'warning'
        })

        if (row.id) {
            await deleteDomain(row.id)
            ElMessage.success('删除成功')
            await loadDomains()
        }
    } catch (error) {
        if (error !== 'cancel') {
            ElMessage.error('删除失败')
        }
    }
}

// 批量操作状态
const selectedRows = ref<Domain[]>([])

const handleSelectionChange = (selection: Domain[]) => {
    selectedRows.value = selection
}

const isRowSelectable = (row: Domain) => {
    if (!copyMode.value) return true
    if (!copySource.value?.id) return true
    return row.id !== copySource.value.id
}

const handleBatchDelete = async () => {
    if (selectedRows.value.length === 0) return

    try {
        await ElMessageBox.confirm(`确定要删除选中的 ${selectedRows.value.length} 个域名吗？`, '批量删除提示', {
            type: 'warning',
            confirmButtonText: '确定删除',
            cancelButtonText: '取消',
            confirmButtonClass: 'el-button--danger'
        })

        const loading = ElMessage.info({
            message: '正在批量删除...',
            duration: 0
        })

        let successCount = 0
        let failCount = 0

        // 并行执行删除操作
        const deletePromises = selectedRows.value.map(async (row: Domain) => {
            if (row.id) {
                try {
                    await deleteDomain(row.id)
                    successCount++
                } catch (error) {
                    console.error(`删除域名 ${row.domain} 失败:`, error)
                    failCount++
                }
            }
        })

        await Promise.all(deletePromises)
        loading.close()

        if (failCount === 0) {
            ElMessage.success(`成功删除 ${successCount} 个域名`)
        } else {
            ElMessage.warning(`删除完成: 成功 ${successCount} 个, 失败 ${failCount} 个`)
        }

        selectedRows.value = [] // 清空选择
        await loadDomains() // 刷新列表

    } catch (error) {
        if (error !== 'cancel') {
            console.error('批量删除出错:', error)
            ElMessage.error('批量删除操作失败')
        }
    }
}

const handleDialogSubmit = async (formData: Omit<Domain, 'id' | 'created_at'>) => {
    try {
        console.log('提交的表单数据:', formData)
        if (isEdit.value && editData.value?.id) {
            const response = await updateDomain(editData.value.id, formData)
            console.log('更新响应:', response)
            ElMessage.success('修改成功')
        } else {
            const response = await createDomain(formData)
            console.log('创建响应:', response)
            ElMessage.success('添加成功')
        }
        dialogVisible.value = false
        await loadDomains()
    } catch (error: any) {
        console.error('保存失败:', error)
        console.error('错误响应:', error.response?.data)
        ElMessage.error(error.response?.data?.message || (isEdit.value ? '修改失败' : '添加失败'))
    }
}

const loadDomains = async (showError = true) => {
    try {
        console.log('开始加载域名列表')
        const authData = auth.getAuthToken()
        if (!authData) {
            throw new Error('未登录或登录已过期')
        }

        const response = await fetch('/api/domains', {
            headers: {
                'Authorization': `Bearer ${authData.token}`,
                'Content-Type': 'application/json'
            }
        })
        console.log('域名列表原始响应:', response)

        if (!response.ok) {
            const errorData = await response.json() as ApiResponse<null>
            throw new Error(errorData.message || '请求失败')
        }

        const result = await response.json() as ApiResponse<Domain[]>
        console.log('解析后的响应:', result)

        if (result.status !== 200) {
            throw new Error(result.message || '请求失败')
        }

        domains.value = result.data || []
        console.log('设置域名列表成功:', domains.value)
    } catch (error: any) {
        console.error('加载域名列表失败:', error)
        console.error('错误详情:', {
            message: error.message,
            stack: error.stack
        })
        if (showError) {
            ElMessage.error(error.message || '加载域名列表失败')
        }
        if (error.message === '未授权访问' || error.message === '无效的访问令牌') {
            auth.clearAuth()
            router.push({ name: 'Login' })
        }
    }
}

const calculateRemainingDays = (expiryDate: string) => {
    if (isPermanentExpiry(expiryDate)) return Number.MAX_SAFE_INTEGER
    const today = new Date()
    today.setHours(0, 0, 0, 0)
    const expiry = new Date(expiryDate)
    expiry.setHours(0, 0, 0, 0)
    const diffTime = expiry.getTime() - today.getTime()
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
    if (diffDays < 0) {
        return 0
    }
    return diffDays
}

const handleConfig = () => {
    configVisible.value = true
}

const handleConfigSubmit = async (config: AlertConfig) => {
    try {
        const authData = auth.getAuthToken()
        if (!authData) {
            throw new Error('未登录或登录已过期')
        }

        const response = await fetch('/api/alertconfig', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authData.token}`
            },
            body: JSON.stringify(config)
        })

        const result = await response.json() as ApiResponse<AlertConfig>

        if (result.status === 200) {
            ElMessage.success('配置保存成功')
            alertDays.value = config.days
            alertConfig.value = {
                ...config,
                auto_check_enabled: config.auto_check_enabled ?? 0,
                auto_check_interval: config.auto_check_interval ?? 30
            }
        } else {
            throw new Error(result.message || '保存失败')
        }
    } catch (error: unknown) {
        console.error('保存配置失败:', error)
        if (error instanceof Error) {
            ElMessage.error(error.message)
            if (error.message === '未授权访问' || error.message === '无效的访问令牌') {
                auth.clearAuth()
                router.push({ name: 'Login' })
            }
        } else {
            ElMessage.error('保存配置失败')
        }
    }
}

const handleRefreshTable = async () => {
    if (refreshingTable.value) return

    try {
        refreshingTable.value = true
        await loadDomains(true)
    } catch (error: unknown) {
        console.error('刷新表格失败:', error)
        ElMessage.error(error instanceof Error ? error.message : '刷新表格失败')
    } finally {
        refreshingTable.value = false
    }
}

const handleRefreshStatus = async (showMessage = true) => {
    if (refreshingStatus.value) return

    try {
        refreshingStatus.value = true
        if (showMessage) {
            ElMessage.info('正在检查域名状态...')
        }
        const authData = auth.getAuthToken()
        if (!authData) {
            throw new Error('未登录或登录已过期')
        }
        const response = await fetch('/api/domains/check-all', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${authData.token}`
            }
        })
        if (response.status === 401) {
            auth.clearAuth()
            router.push({ name: 'Login' })
            throw new Error('未授权访问')
        }
        const result = await response.json() as ApiResponse<Domain[]>
        if (result.status !== 200) {
            throw new Error(result.message || '检查失败')
        }
        domains.value = result.data || []
        if (showMessage) {
            ElMessage.success('状态刷新完成')
        }
    } catch (error: unknown) {
        console.error('刷新状态失败:', error)
        if (showMessage) {
            ElMessage.error(error instanceof Error ? error.message : '刷新状态失败')
        }
    } finally {
        refreshingStatus.value = false
    }
}

const scheduleCertStatusRefresh = () => {
    if (certStatusRefreshTimer) return
    certStatusRefreshTimer = window.setTimeout(async () => {
        certStatusRefreshTimer = null
        await loadDomains(false)
    }, 300)
}

const connectCertStatusStream = () => {
    if (certStatusSource) return
    const authData = auth.getAuthToken()
    if (!authData) return
    const url = `/api/events/cert-status?token=${encodeURIComponent(authData.token)}`
    const source = new EventSource(url)
    certStatusSource = source
    source.onopen = () => {
        scheduleCertStatusRefresh()
    }
    source.onmessage = () => {
        scheduleCertStatusRefresh()
    }
    source.onerror = () => {
        if (certStatusSource) {
            certStatusSource.close()
            certStatusSource = null
        }
        if (certStatusReconnectTimer) return
        certStatusReconnectTimer = window.setTimeout(() => {
            certStatusReconnectTimer = null
            connectCertStatusStream()
        }, 3000)
    }
}

const stopCertStatusStream = () => {
    if (certStatusSource) {
        certStatusSource.close()
        certStatusSource = null
    }
    if (certStatusReconnectTimer) {
        clearTimeout(certStatusReconnectTimer)
        certStatusReconnectTimer = null
    }
    if (certStatusRefreshTimer) {
        clearTimeout(certStatusRefreshTimer)
        certStatusRefreshTimer = null
    }
}

const loadWebsiteConfigs = async () => {
    try {
        const authData = auth.getAuthToken()
        if (!authData) {
            throw new Error('未登录或登录已过期')
        }
        const response = await fetch('/api/websites', {
            headers: {
                'Authorization': `Bearer ${authData.token}`,
                'Content-Type': 'application/json'
            }
        })
        const result = await response.json() as ApiResponse<WebsiteConfig[]>
        if (result.status !== 200) {
            throw new Error(result.message || '获取网站配置失败')
        }
        websiteConfigs.value = result.data || []
    } catch (error: unknown) {
        console.error('获取网站配置失败:', error)
    }
}

const loadServerIp = async () => {
    try {
        const authData = auth.getAuthToken()
        if (!authData) {
            throw new Error('未登录或登录已过期')
        }
        const response = await fetch('/api/system/ip', {
            headers: {
                'Authorization': `Bearer ${authData.token}`,
                'Content-Type': 'application/json'
            }
        })
        const result = await response.json() as ApiResponse<{ ip: string }>
        if (result.status !== 200) {
            throw new Error(result.message || '获取服务器 IP 失败')
        }
        serverIp.value = result.data?.ip || ''
    } catch (error) {
        console.error('获取服务器 IP 失败:', error)
    }
}

// 在组件加载时获取告警配置
const loadAlertConfig = async () => {
    try {
        const authData = auth.getAuthToken()
        if (!authData) {
            throw new Error('未登录或登录已过期')
        }

        const response = await fetch('/api/alertconfig', {
            headers: {
                'Authorization': `Bearer ${authData.token}`,
                'Content-Type': 'application/json'
            }
        })
        const result = await response.json() as ApiResponse<AlertConfig>

        if (result.status === 200) {
            if (result.data) {
                alertConfig.value = {
                    ...result.data,
                    auto_check_enabled: result.data.auto_check_enabled ?? 0,
                    auto_check_interval: result.data.auto_check_interval ?? 30
                }
                alertDays.value = result.data.days
            } else {
                alertConfig.value = {
                    tg_token: '',
                    tg_userid: '',
                    wx_api: '',
                    wx_token: '',
                    days: 30,
                    auto_check_enabled: 0,
                    auto_check_interval: 30
                }
                alertDays.value = 30
            }
        } else {
            throw new Error(result.message || '获取配置失败')
        }
    } catch (error: unknown) {
        console.error('获取告警配置失败:', error)
        if (error instanceof Error) {
            if (error.message === '未授权访问' || error.message === '无效的访问令牌') {
                auth.clearAuth()
                router.push({ name: 'Login' })
            }
        }
    }
}

const handleImport = () => {
    importVisible.value = true
}

const handleExport = async () => {
    try {
        const authData = auth.getAuthToken()
        if (!authData) {
            throw new Error('未登录或登录已过期')
        }

        // 显示加载提示
        const loading = ElMessage.info({
            message: '正在准备导出数据...',
            duration: 0
        })

        // 直接使用浏览器下载功能
        const response = await fetch('/api/domains/export', {
            headers: {
                'Authorization': `Bearer ${authData.token}`
            }
        })

        // 关闭加载提示
        loading.close()

        if (!response.ok) {
            const errorData = await response.json() as ApiResponse<null>
            throw new Error(errorData.message || '导出失败')
        }

        // 获取文件名
        const filename = response.headers.get('Content-Disposition')?.split('filename=')[1]?.replace(/"/g, '') || `domains-export-${new Date().toISOString().split('T')[0]}.json`

        // 创建 Blob 并下载
        const blob = await response.blob()
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = filename
        document.body.appendChild(a)
        a.click()
        window.URL.revokeObjectURL(url)
        document.body.removeChild(a)

        ElMessage.success('导出成功')
    } catch (error) {
        console.error('导出失败:', error)
        ElMessage.error(error instanceof Error ? error.message : '导出失败')
    }
}

// 切换暗黑模式
const toggleDarkMode = () => {
    localStorage.setItem('darkMode', isDarkMode.value.toString())
    document.documentElement.classList.toggle('dark', isDarkMode.value)
}

// 初始化暗黑模式
onMounted(() => {
    if (isDarkMode.value) {
        document.documentElement.classList.add('dark')
    }
    checkLoginStatus()
    loadDomains()
    loadAlertConfig()
    loadWebsiteConfigs()
    loadServerIp()
    connectCertStatusStream()
})

onBeforeUnmount(() => {
    stopCertStatusStream()
})
</script>

<style scoped>
.home-container {
    min-height: 100vh;
    padding: 20px;
    padding-bottom: 80px;
    background: linear-gradient(135deg, #f5f7fa 0%, #e4e7eb 100%);
    transition: background 0.3s ease;
}

.home-container.dark-mode {
    background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
    color: #ffffff;
}

.header {
    display: flex;
    flex-wrap: wrap;
    gap: 15px;
    margin-bottom: 20px;
    align-items: center;
    justify-content: space-between;
    background: linear-gradient(135deg, #E3F2FD 0%, #BBDEFB 100%);
    padding: 15px 20px;
    border-radius: 8px;
    box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
    transition: all 0.3s ease;
}

.dark-mode .header {
    background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
    color: #ffffff;
}

.header h2 {
    margin: 0;
    color: #1976D2;
    font-size: 24px;
    text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.1);
    transition: all 0.3s ease;
}

.dark-mode .header h2 {
    color: #64B5F6;
}

.header-buttons {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    align-items: center;
}

.theme-switch {
    margin-left: 4px;
    --el-switch-on-color: #2c3e50;
}

/* 增强白天模式下太阳图标的可见性 */
:deep(.el-switch__action .el-icon) {
    color: #ffffff;
}

:deep(.el-switch .el-icon) {
    color: #ffffff;
}

.table-operations {
    margin-bottom: 15px;
    display: flex;
    justify-content: space-between; /* 改为两端对齐，左边放批量操作，右边放搜索 */
    align-items: center;
}

.batch-delete-btn {
    transition: all 0.3s ease;
    animation: fadeIn 0.3s ease;
}

@keyframes fadeIn {
    from { opacity: 0; transform: translateX(-10px); }
    to { opacity: 1; transform: translateX(0); }
}

.search-input {
    width: 300px;
    transition: all 0.3s;
}

.search-input:hover, .search-input:focus-within {
    width: 350px;
}

.pagination-container {
    margin-top: 20px;
    display: flex;
    justify-content: center;
    padding-bottom: 20px;
}

:deep(.highlight) {
    color: #f56c6c;
    font-weight: bold;
    background-color: rgba(245, 108, 108, 0.1);
    padding: 0 2px;
    border-radius: 2px;
}

.dark-mode :deep(.highlight) {
    color: #ff9090;
    background-color: rgba(255, 144, 144, 0.2);
}

.custom-table {
    margin-bottom: 60px;
    overflow-x: auto;
    background: white;
    border-radius: 8px;
    box-shadow: 0 2px 12px 0 rgba(0, 0, 0, 0.1);
    transition: all 0.3s ease;
}

.dark-mode .custom-table {
    background: #1d1e1f;
    color: #ffffff;
}

:deep(.el-table) {
    width: 100% !important;
    white-space: nowrap;
    border-radius: 8px;
    overflow: hidden;
    transition: all 0.3s ease;
}

.dark-mode :deep(.el-table) {
    --el-table-border-color: #363637;
    --el-table-header-bg-color: #252526;
    --el-table-row-hover-bg-color: #2c2c2d;
    --el-table-current-row-bg-color: #2c2c2d;
    --el-table-header-text-color: #ffffff;
    --el-table-text-color: #ffffff;
    --el-table-bg-color: #1d1e1f;
    --el-table-tr-bg-color: #1d1e1f;
    --el-table-expanded-cell-bg-color: #1d1e1f;
}

.link {
    color: #409EFF;
    text-decoration: none;
    transition: color 0.3s;
}

.link:hover {
    color: #66b1ff;
    text-decoration: underline;
}

.warning-text {
    color: #E6A23C;
    font-weight: bold;
}

.success-text {
    color: #67C23A;
    font-weight: bold;
}

.danger-text {
    color: #F56C6C;
    font-weight: bold;
}

:deep(.el-table th) {
    background-color: #f5f7fa !important;
}

.dark-mode :deep(.el-table th) {
    background-color: #252526 !important;
    color: #ffffff !important;
    font-weight: bold;
    border-bottom-color: #363637;
}

:deep(.el-table--striped .el-table__body tr.el-table__row--striped td) {
    background-color: #fafafa;
}

.dark-mode :deep(.el-table--striped .el-table__body tr.el-table__row--striped td) {
    background-color: #252526;
}

.el-button {
    border-radius: 4px;
}

/* 添加图标的过渡效果 */
.el-icon {
    margin-right: 4px;
    transition: transform 0.3s;
}

.el-button:hover .el-icon {
    transform: rotate(180deg);
}

.header-buttons .el-button {
    min-width: 88px;
    transition: all 0.3s;
}

.header-buttons .el-button:hover {
    transform: translateY(-2px);
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.header-buttons .el-button [class*="el-icon"] {
    margin-right: 4px;
    transition: transform 0.3s;
}

.header-buttons .el-button:not(.is-loading):hover [class*="el-icon"] {
    transform: rotate(180deg);
}

/* 表格中的按钮样式 */
.el-table .el-button {
    transition: all 0.3s;
}

.el-table .el-button:hover {
    transform: translateY(-1px);
    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
}

.el-table .el-button [class*="el-icon"] {
    margin-right: 4px;
}

/* 加载状态的特殊样式 */
.el-button.is-loading {
    opacity: 0.8;
    cursor: not-allowed;
}

.el-button.is-loading [class*="el-icon"] {
    animation: none;
}

.footer {
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    padding: 16px;
    background: white;
    box-shadow: 0 -2px 10px rgba(0, 0, 0, 0.05);
    transition: all 0.3s ease;
}

.dark-mode .footer {
    background: #2d2d2d;
    color: #ffffff;
}

.footer-content {
    max-width: 1200px;
    margin: 0 auto;
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 10px;
    text-align: center;
}

.copyright {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 8px;
    font-size: 14px;
}

.separator {
    color: #dcdfe6;
    margin: 0 2px;
}

.social-links {
    display: flex;
    gap: 15px;
    align-items: center;
}

.social-link {
    color: #606266;
    transition: all 0.3s ease;
    display: flex;
    align-items: center;
    padding: 2px;
}

.social-link:hover {
    color: #409EFF;
    transform: translateY(-2px);
}

.social-icon {
    width: 20px;
    height: 20px;
}

@media (max-width: 768px) {
    .home-container {
        padding: 15px;
        padding-bottom: 70px;
    }

    .header {
        padding: 12px;
        margin-bottom: 12px;
    }

    .header h2 {
        font-size: 1.2rem;
    }

    .custom-table {
        margin-bottom: 15px;
    }

    .footer {
        padding: 10px;
        height: auto;
        min-height: 50px;
    }

    .footer-content {
        flex-direction: column;
        gap: 8px;
        text-align: center;
    }

    .copyright {
        font-size: 0.8rem;
        gap: 6px;
    }

    .social-links {
        gap: 10px;
    }

    .social-icon {
        width: 16px;
        height: 16px;
    }

    :deep(.el-table) {
        font-size: 0.9rem;
    }

    :deep(.el-table th),
    :deep(.el-table td) {
        padding: 8px 4px;
    }

    :deep(.el-button) {
        padding: 6px 12px;
        font-size: 0.8rem;
    }
}

@media (max-width: 480px) {
    .home-container {
        padding: 10px;
        padding-bottom: 60px;
    }

    .header {
        padding: 10px;
    }

    .header-buttons {
        gap: 5px;
    }
}
</style>

<style>
/* 全局暗黑模式样式 */
.dark {
    --el-bg-color: #1a1a1a;
    --el-bg-color-overlay: #2d2d2d;
    --el-text-color-primary: #ffffff;
    --el-text-color-regular: #e0e0e0;
    --el-border-color: #404040;
    --el-border-color-light: #404040;
    --el-border-color-lighter: #404040;
    --el-border-color-extra-light: #404040;
    --el-fill-color-blank: #2d2d2d;
    --el-mask-color: rgba(0, 0, 0, 0.8);
}

.dark .el-dialog {
    --el-dialog-bg-color: #2d2d2d;
    --el-dialog-title-font-color: #ffffff;
}

/* 弹出对话框圆角样式 */
.el-dialog {
    border-radius: 12px !important;
    overflow: hidden;
}

.el-dialog__header {
    border-radius: 12px 12px 0 0 !important;
}

.el-dialog__body {
    border-radius: 0 0 12px 12px !important;
}

/* 背景模糊效果 */
.el-overlay {
    backdrop-filter: blur(5px) !important;
    background-color: rgba(0, 0, 0, 0.5) !important;
}

.dark .el-card {
    --el-card-bg-color: #2d2d2d;
}

/* 移除按钮的暗黑模式样式 */
.dark .el-button {
    --el-button-bg-color: var(--el-color-primary);
    --el-button-border-color: var(--el-color-primary);
    --el-button-hover-bg-color: var(--el-color-primary-light-3);
    --el-button-hover-border-color: var(--el-color-primary-light-3);
}

.dark .el-button--danger {
    --el-button-bg-color: var(--el-color-danger);
    --el-button-border-color: var(--el-color-danger);
    --el-button-hover-bg-color: var(--el-color-danger-light-3);
    --el-button-hover-border-color: var(--el-color-danger-light-3);
}

.dark .el-input {
    --el-input-bg-color: #2d2d2d;
    --el-input-text-color: #ffffff;
    --el-input-border-color: #404040;
}

.dark .el-select {
    --el-select-border-color-hover: #505050;
    --el-select-input-focus-border-color: #505050;
}

.el-button.el-button--small {
    padding: 6px 12px;
    /* 默认是 8px 15px */
    font-size: 12px;
    /* 默认是 13px */
}

/* Dark mode pagination fixes */
.dark .el-pagination.is-background .el-pager li:not(.is-active) {
    background-color: #2d2d2d;
    color: #ffffff;
}

.dark .el-pagination.is-background .btn-prev,
.dark .el-pagination.is-background .btn-next {
    background-color: #2d2d2d;
    color: #ffffff;
}

.dark .el-pagination.is-background .el-pager li:not(.is-active):hover {
    color: #409EFF;
    color: #dcdfe6;
    margin: 0 2px;
}

.social-links {
    display: flex;
    gap: 15px;
    align-items: center;
}

.social-link {
    color: #606266;
    transition: all 0.3s ease;
    display: flex;
    align-items: center;
    padding: 2px;
}

.social-link:hover {
    color: #409EFF;
    transform: translateY(-2px);
}

.social-icon {
    width: 20px;
    height: 20px;
}

@media (max-width: 768px) {
    .home-container {
        padding: 15px;
        padding-bottom: 70px;
    }

    .header {
        padding: 12px;
        margin-bottom: 12px;
    }

    .header h2 {
        font-size: 1.2rem;
    }

    .custom-table {
        margin-bottom: 15px;
    }

    .footer {
        padding: 10px;
        height: auto;
        min-height: 50px;
    }

    .footer-content {
        flex-direction: column;
        gap: 8px;
        text-align: center;
    }

    .copyright {
        font-size: 0.8rem;
        gap: 6px;
    }

    .social-links {
        gap: 10px;
    }

    .social-icon {
        width: 16px;
        height: 16px;
    }

    :deep(.el-table) {
        font-size: 0.9rem;
    }

    :deep(.el-table th),
    :deep(.el-table td) {
        padding: 8px 4px;
    }

    :deep(.el-button) {
        padding: 6px 12px;
        font-size: 0.8rem;
    }
}

@media (max-width: 480px) {
    .home-container {
        padding: 10px;
        padding-bottom: 60px;
    }

    .header {
        padding: 10px;
    }

    .header-buttons {
        gap: 5px;
    }
}
</style>

<style>
/* 全局暗黑模式样式 */
.dark {
    --el-bg-color: #1a1a1a;
    --el-bg-color-overlay: #2d2d2d;
    --el-text-color-primary: #ffffff;
    --el-text-color-regular: #e0e0e0;
    --el-border-color: #404040;
    --el-border-color-light: #404040;
    --el-border-color-lighter: #404040;
    --el-border-color-extra-light: #404040;
    --el-fill-color-blank: #2d2d2d;
    --el-mask-color: rgba(0, 0, 0, 0.8);
}

.dark .el-dialog {
    --el-dialog-bg-color: #2d2d2d;
    --el-dialog-title-font-color: #ffffff;
}

/* 弹出对话框圆角样式 */
.el-dialog {
    border-radius: 12px !important;
    overflow: hidden;
}

.el-dialog__header {
    border-radius: 12px 12px 0 0 !important;
}

.el-dialog__body {
    border-radius: 0 0 12px 12px !important;
}

/* 背景模糊效果 */
.el-overlay {
    backdrop-filter: blur(5px) !important;
    background-color: rgba(0, 0, 0, 0.5) !important;
}

.dark .el-card {
    --el-card-bg-color: #2d2d2d;
}

/* 移除按钮的暗黑模式样式 */
.dark .el-button {
    --el-button-bg-color: var(--el-color-primary);
    --el-button-border-color: var(--el-color-primary);
    --el-button-hover-bg-color: var(--el-color-primary-light-3);
    --el-button-hover-border-color: var(--el-color-primary-light-3);
}

.dark .el-button--danger {
    --el-button-bg-color: var(--el-color-danger);
    --el-button-border-color: var(--el-color-danger);
    --el-button-hover-bg-color: var(--el-color-danger-light-3);
    --el-button-hover-border-color: var(--el-color-danger-light-3);
}

.dark .el-input {
    --el-input-bg-color: #2d2d2d;
    --el-input-text-color: #ffffff;
    --el-input-border-color: #404040;
}

.dark .el-select {
    --el-select-border-color-hover: #505050;
    --el-select-input-focus-border-color: #505050;
}

.el-button.el-button--small {
    padding: 6px 12px;
    /* 默认是 8px 15px */
    font-size: 12px;
    /* 默认是 13px */
}

/* Dark mode pagination fixes */
.dark .el-pagination.is-background .el-pager li:not(.is-active) {
    background-color: #2d2d2d;
    color: #ffffff;
}

.dark .el-pagination.is-background .btn-prev,
.dark .el-pagination.is-background .btn-next {
    background-color: #2d2d2d;
    color: #ffffff;
}

.dark .el-pagination.is-background .el-pager li:not(.is-active):hover {
    color: #409EFF;
}

.dark .el-pagination__jump {
    color: #ffffff;
}</style>
