<template>
    <el-dialog v-model="dialogVisible" title="参数配置" width="600px">
        <el-form ref="formRef" :model="form" :rules="rules" label-width="140px">
            <el-collapse v-model="activeNames">
                <el-collapse-item title="TG" name="1">
                    <el-form-item label="TG-token" prop="tg_token">
                        <el-input v-model="form.tg_token" placeholder="请输入 Telegram Bot Token" id="tg-token-input" />
                    </el-form-item>
                    <el-form-item label="TG-userid" prop="tg_userid">
                        <el-input v-model="form.tg_userid" placeholder="请输入 Telegram User ID" id="tg-userid-input" />
                    </el-form-item>
                </el-collapse-item>
                <el-collapse-item title="微信" name="2">
                    <el-form-item label="WX-API" prop="wx_api">
                        <el-input v-model="form.wx_api" placeholder="请输入 WX-API" id="wx-api-input" />
                    </el-form-item>
                    <el-form-item label="WX-token" prop="wx_token">
                        <el-input v-model="form.wx_token" placeholder="请输入 WX-token" id="wx-token-input" />
                    </el-form-item>
                </el-collapse-item>
                <el-collapse-item title="静态网站" name="3">
                    <el-form-item label="网站名称">
                        <el-input v-model="newWebsite.name" placeholder="请输入网站名称" id="website-name-input" />
                    </el-form-item>
                    <el-form-item label="文件名">
                        <el-select v-model="newWebsite.filename" placeholder="请选择文件" id="website-file-input" clearable>
                            <el-option v-for="file in websiteFiles" :key="file" :label="file" :value="file" />
                        </el-select>
                    </el-form-item>
                    <el-form-item>
                        <el-button type="primary" @click="handleAddWebsite">新增</el-button>
                        <el-button type="danger" :disabled="selectedWebsites.length === 0" @click="handleDeleteWebsites">
                            删除
                        </el-button>
                    </el-form-item>
                    <el-table :data="websites" border style="width: 100%" @selection-change="handleWebsiteSelectionChange">
                        <el-table-column type="selection" width="55" />
                        <el-table-column prop="name" label="网站名称" />
                        <el-table-column prop="filename" label="文件名" />
                    </el-table>
                </el-collapse-item>
                <el-collapse-item title="CF账号" name="4">
                    <el-form-item label="账号email">
                        <el-input v-model="newCfAccount.email" placeholder="请输入账号email" id="cf-email-input" />
                    </el-form-item>
                    <el-form-item label="全局token">
                        <el-input v-model="newCfAccount.token" placeholder="请输入全局token" id="cf-token-input" />
                    </el-form-item>
                    <el-form-item>
                        <el-button type="primary" @click="handleAddCfAccount">增加</el-button>
                        <el-button type="danger" :disabled="selectedCfAccounts.length === 0" @click="handleDeleteCfAccounts">
                            删除
                        </el-button>
                    </el-form-item>
                    <el-table :data="cfAccounts" border style="width: 100%" @selection-change="handleCfAccountSelectionChange">
                        <el-table-column type="selection" width="55" />
                        <el-table-column prop="email" label="账号email" />
                        <el-table-column prop="token" label="token" />
                    </el-table>
                </el-collapse-item>
            </el-collapse>
            <el-form-item label="剩余多少天告警" prop="days">
                <el-input-number v-model="form.days" :min="1" :max="365" id="days-input" />
            </el-form-item>
            <el-form-item label="自动检查域名状态" prop="auto_check_enabled">
                <el-switch v-model="form.auto_check_enabled" :active-value="1" :inactive-value="0" inline-prompt
                    active-text="开启" inactive-text="关闭" id="auto-check-enabled-input" />
            </el-form-item>
            <el-form-item v-if="form.auto_check_enabled === 1" label="每隔多少分钟检查" prop="auto_check_interval">
                <el-input-number v-model="form.auto_check_interval" :min="1" :max="1440" id="auto-check-interval-input" />
            </el-form-item>
        </el-form>
        <template #footer>
            <span class="dialog-footer">
                <el-button @click="dialogVisible = false">取消</el-button>
                <el-button type="primary" @click="handleSubmit">提交</el-button>
            </span>
        </template>
    </el-dialog>
</template>

<script setup lang="ts">
import type { FormInstance, FormRules } from 'element-plus'
import { ElMessage } from 'element-plus'
import { defineEmits, defineProps, ref, watch } from 'vue'
import { useAuth } from '../utils/auth'

interface AlertConfigForm {
    tg_token: string
    tg_userid: string
    wx_api: string
    wx_token: string
    days: number
    auto_check_enabled: number
    auto_check_interval: number
}

const props = defineProps<{
    visible: boolean
    config?: AlertConfigForm
}>()

const emit = defineEmits(['update:visible', 'submit', 'websites-updated', 'cf-accounts-updated'])

const dialogVisible = ref(props.visible)
const formRef = ref<FormInstance>()
const activeNames = ref(['1', '2', '3', '4'])

const form = ref<AlertConfigForm>({
    tg_token: '',
    tg_userid: '',
    wx_api: '',
    wx_token: '',
    days: 30,
    auto_check_enabled: 0,
    auto_check_interval: 30
})

interface WebsiteConfig {
    id: number
    name: string
    filename: string
}

const websites = ref<WebsiteConfig[]>([])
const websiteFiles = ref<string[]>([])
const selectedWebsites = ref<WebsiteConfig[]>([])
const newWebsite = ref({ name: '', filename: '' })

interface CfAccount {
    id: number
    email: string
    token: string
}

const cfAccounts = ref<CfAccount[]>([])
const selectedCfAccounts = ref<CfAccount[]>([])
const newCfAccount = ref({ email: '', token: '' })

const rules = {
    days: [
        { required: true, message: '请输入告警天数', trigger: 'change' }
    ],
    auto_check_interval: [
        {
            validator: (_rule: unknown, value: number, callback: (error?: Error) => void) => {
                if (form.value.auto_check_enabled !== 1) {
                    callback()
                    return
                }
                if (!value || value < 1) {
                    callback(new Error('请输入检查间隔'))
                    return
                }
                callback()
            },
            trigger: 'change'
        }
    ]
} satisfies FormRules

watch(() => props.visible, (newVal: boolean) => {
    dialogVisible.value = newVal
})

watch(dialogVisible, (newVal: boolean) => {
    emit('update:visible', newVal)
    if (newVal) {
        loadWebsiteConfigs()
        loadWebsiteFiles()
        loadCfAccounts()
    }
})

watch(() => props.config, (newVal: AlertConfigForm | undefined) => {
    if (newVal) {
        form.value = { ...form.value, ...newVal }
    }
}, { immediate: true })

const handleSubmit = async () => {
    if (!formRef.value) return

    await formRef.value.validate((valid: boolean) => {
        if (valid) {
            emit('submit', form.value)
            dialogVisible.value = false
        }
    })
}

const loadWebsiteConfigs = async () => {
    try {
        const auth = useAuth()
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
        const result = await response.json() as { status: number; message: string; data: WebsiteConfig[] }
        if (result.status !== 200) {
            throw new Error(result.message || '获取失败')
        }
        websites.value = result.data || []
    } catch (error) {
        ElMessage.error(error instanceof Error ? error.message : '获取失败')
    }
}

const loadWebsiteFiles = async () => {
    try {
        const auth = useAuth()
        const authData = auth.getAuthToken()
        if (!authData) {
            throw new Error('未登录或登录已过期')
        }
        const response = await fetch('/api/websites/files', {
            headers: {
                'Authorization': `Bearer ${authData.token}`,
                'Content-Type': 'application/json'
            }
        })
        const result = await response.json() as { status: number; message: string; data: string[] }
        if (result.status !== 200) {
            throw new Error(result.message || '获取失败')
        }
        websiteFiles.value = result.data || []
    } catch (error) {
        ElMessage.error(error instanceof Error ? error.message : '获取失败')
    }
}

const handleAddWebsite = async () => {
    try {
        if (!newWebsite.value.name || !newWebsite.value.filename) {
            ElMessage.warning('请输入名称并选择文件')
            return
        }
        const auth = useAuth()
        const authData = auth.getAuthToken()
        if (!authData) {
            throw new Error('未登录或登录已过期')
        }
        const response = await fetch('/api/websites', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authData.token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(newWebsite.value)
        })
        const result = await response.json() as { status: number; message: string }
        if (result.status !== 200) {
            throw new Error(result.message || '创建失败')
        }
        newWebsite.value = { name: '', filename: '' }
        await loadWebsiteConfigs()
        emit('websites-updated')
        ElMessage.success('创建成功')
    } catch (error) {
        ElMessage.error(error instanceof Error ? error.message : '创建失败')
    }
}

const handleWebsiteSelectionChange = (selection: WebsiteConfig[]) => {
    selectedWebsites.value = selection
}

const handleDeleteWebsites = async () => {
    try {
        if (selectedWebsites.value.length === 0) {
            ElMessage.warning('请选择要删除的记录')
            return
        }
        const auth = useAuth()
        const authData = auth.getAuthToken()
        if (!authData) {
            throw new Error('未登录或登录已过期')
        }
        const response = await fetch('/api/websites', {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${authData.token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ids: selectedWebsites.value.map((item: WebsiteConfig) => item.id) })
        })
        const result = await response.json() as { status: number; message: string }
        if (result.status !== 200) {
            throw new Error(result.message || '删除失败')
        }
        selectedWebsites.value = []
        await loadWebsiteConfigs()
        emit('websites-updated')
        ElMessage.success('删除成功')
    } catch (error) {
        ElMessage.error(error instanceof Error ? error.message : '删除失败')
    }
}

const loadCfAccounts = async () => {
    try {
        const auth = useAuth()
        const authData = auth.getAuthToken()
        if (!authData) {
            throw new Error('未登录或登录已过期')
        }
        const response = await fetch('/api/cf-accounts', {
            headers: {
                'Authorization': `Bearer ${authData.token}`,
                'Content-Type': 'application/json'
            }
        })
        const result = await response.json() as { status: number; message: string; data: CfAccount[] }
        if (result.status !== 200) {
            throw new Error(result.message || '获取失败')
        }
        cfAccounts.value = result.data || []
    } catch (error) {
        ElMessage.error(error instanceof Error ? error.message : '获取失败')
    }
}

const handleAddCfAccount = async () => {
    try {
        if (!newCfAccount.value.email || !newCfAccount.value.token) {
            ElMessage.warning('请输入账号和token')
            return
        }
        const auth = useAuth()
        const authData = auth.getAuthToken()
        if (!authData) {
            throw new Error('未登录或登录已过期')
        }
        const response = await fetch('/api/cf-accounts', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${authData.token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(newCfAccount.value)
        })
        const result = await response.json() as { status: number; message: string; data: CfAccount }
        if (result.status !== 200) {
            throw new Error(result.message || '创建失败')
        }
        ElMessage.success('新增成功')
        newCfAccount.value = { email: '', token: '' }
        await loadCfAccounts()
        emit('cf-accounts-updated')
    } catch (error) {
        ElMessage.error(error instanceof Error ? error.message : '创建失败')
    }
}

const handleCfAccountSelectionChange = (selection: CfAccount[]) => {
    selectedCfAccounts.value = selection
}

const handleDeleteCfAccounts = async () => {
    try {
        if (selectedCfAccounts.value.length === 0) {
            ElMessage.warning('请选择要删除的账号')
            return
        }
        const auth = useAuth()
        const authData = auth.getAuthToken()
        if (!authData) {
            throw new Error('未登录或登录已过期')
        }
        const ids = selectedCfAccounts.value.map((item: CfAccount) => item.id)
        const response = await fetch('/api/cf-accounts', {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${authData.token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ids })
        })
        const result = await response.json() as { status: number; message: string }
        if (result.status !== 200) {
            throw new Error(result.message || '删除失败')
        }
        ElMessage.success('删除成功')
        selectedCfAccounts.value = []
        await loadCfAccounts()
        emit('cf-accounts-updated')
    } catch (error) {
        ElMessage.error(error instanceof Error ? error.message : '删除失败')
    }
}
</script>

<style scoped>
.dialog-footer {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
}
</style>
