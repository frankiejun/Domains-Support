<template>
    <el-dialog v-model="dialogVisible" :title="isEdit ? '修改域名' : '新建域名'" width="600px">
        <el-form ref="formRef" :model="form" :rules="rules" label-width="100px" label-position="right">
            <el-form-item label="域名" prop="domain">
                <el-input v-model="form.domain" placeholder="请输入域名" id="domain-input" autocomplete="off" clearable />
            </el-form-item>
            <el-form-item label="域名商" prop="registrar">
                <el-input v-model="form.registrar" placeholder="请输入域名商" id="registrar-input" autocomplete="off"
                    clearable />
            </el-form-item>
            <el-form-item label="域名商链接" prop="registrar_link">
                <el-input v-model="form.registrar_link" placeholder="请输入域名商链接" id="registrar-link-input"
                    autocomplete="off" clearable />
            </el-form-item>
            <el-form-item label="注册日期" prop="registrar_date">
                <el-date-picker v-model="form.registrar_date" type="date" placeholder="选择注册日期" value-format="YYYY-MM-DD"
                    id="registrar-date-input" autocomplete="off" clearable />
            </el-form-item>
            <el-form-item label="到期日期" prop="expiry_date">
                <el-date-picker v-model="form.expiry_date" type="date" placeholder="选择到期日期" value-format="YYYY-MM-DD"
                    :shortcuts="expiryDateShortcuts" id="expiry-date-input" autocomplete="off" clearable />
            </el-form-item>
            <el-form-item label="服务类型" prop="service_type">
                <el-select v-model="form.service_type" placeholder="请选择服务类型" id="service-type-input" autocomplete="off"
                    clearable>
                    <el-option label="伪装网站" value="伪装网站" />
                    <el-option label="正常网站" value="正常网站" />
                    <el-option label="其他" value="其他" />
                </el-select>
            </el-form-item>
            <el-form-item label="状态" prop="status">
                <el-select v-model="form.status" placeholder="请选择状态" id="status-input" autocomplete="off" clearable>
                    <el-option label="在线" value="在线" />
                    <el-option label="离线" value="离线" />
                </el-select>
            </el-form-item>
            <el-form-item label="到期通知">
                <el-switch v-model="form.tgsend" :active-value="1" :inactive-value="0" inline-prompt active-text="开启"
                    inactive-text="关闭" id="tgsend-input" autocomplete="off" />
            </el-form-item>
            <el-form-item label="域名离线通知">
                <el-switch v-model="form.st_tgsend" :active-value="1" :inactive-value="0" inline-prompt active-text="开启"
                    inactive-text="关闭" id="st-tgsend-input" autocomplete="off" />
            </el-form-item>
            <el-form-item label="备注" prop="memo">
                <el-input v-model="form.memo" type="textarea" :rows="3" placeholder="请输入备注" id="memo-input"
                    autocomplete="off" clearable />
            </el-form-item>
        </el-form>
        <template #footer>
            <span class="dialog-footer">
                <el-button @click="handleCancel">取消</el-button>
                <el-button type="primary" @click="handleSubmit">确定</el-button>
            </span>
        </template>
    </el-dialog>
</template>

<script setup lang="ts">
import type { FormInstance, FormRules } from 'element-plus'
import { defineEmits, defineProps, ref, watch } from 'vue'

interface DomainForm {
    domain: string
    registrar: string
    registrar_link: string
    registrar_date: string
    expiry_date: string
    service_type: string
    status: string
    tgsend: number
    st_tgsend: number
    memo: string
}

const props = defineProps<{
    visible: boolean
    isEdit: boolean
    editData?: DomainForm
}>()

const emit = defineEmits(['update:visible', 'submit'])

const dialogVisible = ref(props.visible)
const formRef = ref<FormInstance>()

const parseBaseDate = (baseDate: string) => {
    const parsed = new Date(baseDate)
    if (!Number.isNaN(parsed.getTime())) return parsed
    return new Date()
}

const buildExpiryDate = (baseDate: string, yearsToAdd: number) => {
    const base = parseBaseDate(baseDate)
    return new Date(base.getFullYear() + yearsToAdd, base.getMonth(), base.getDate())
}

const expiryDateShortcuts = [
    {
        text: '永久',
        value: () => new Date(2099, 11, 31)
    },
    ...Array.from({ length: 10 }, (_, index) => {
        const years = index + 1
        return {
            text: `${years}年`,
            value: () => buildExpiryDate(form.value.registrar_date, years)
        }
    })
]

// 默认表单数据
const defaultForm: DomainForm = {
    domain: '',
    registrar: '',
    registrar_link: '',
    registrar_date: '',
    expiry_date: '',
    service_type: '其他',
    status: '在线',
    tgsend: 1,
    st_tgsend: 0,
    memo: ''
}

// 表单数据
const form = ref<DomainForm>({ ...defaultForm })

// 表单验证规则
const rules = {
    domain: [
        { required: true, message: '请输入域名', trigger: ['blur'] as const },
        { pattern: /^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$/, message: '请输入正确的域名格式', trigger: ['blur'] as const }
    ],
    registrar: [
        { required: true, message: '请输入域名商', trigger: ['blur'] as const }
    ],
    registrar_date: [
        { required: true, message: '请选择注册日期', trigger: ['change'] as const }
    ],
    expiry_date: [
        { required: true, message: '请选择到期日期', trigger: ['change'] as const }
    ],
    service_type: [
        { required: true, message: '请选择服务类型', trigger: ['change'] as const }
    ],
    status: [
        { required: true, message: '请选择状态', trigger: ['change'] as const }
    ]
} satisfies FormRules

// 监听对话框可见性
watch(() => props.visible, (newVal: boolean) => {
    dialogVisible.value = newVal
    if (newVal) {
        if (props.editData) {
            form.value = { ...props.editData }
        } else {
            form.value = { ...defaultForm }
        }
    }
})

// 监听对话框关闭
watch(dialogVisible, (newVal: boolean) => {
    emit('update:visible', newVal)
    if (!newVal) {
        formRef.value?.resetFields()
    }
})

// 监听编辑数据
watch(() => props.editData, (newVal: DomainForm | undefined) => {
    if (newVal) {
        form.value = { ...newVal }
    }
}, { immediate: true })

// 取消按钮处理
const handleCancel = () => {
    dialogVisible.value = false
    formRef.value?.resetFields()
}

// 提交表单
const handleSubmit = async () => {
    if (!formRef.value) return

    await formRef.value.validate((valid, fields) => {
        if (valid) {
            emit('submit', form.value)
            dialogVisible.value = false
        } else {
            console.error('表单验证失败:', fields)
        }
    })
}
</script>

<style scoped>
.dialog-footer {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
}
</style>
