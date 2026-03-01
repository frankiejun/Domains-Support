import request from '../utils/request'

export interface DomainData {
    id?: number
    domain: string
    registrar: string
    registrar_link: string
    registrar_date: string
    expiry_date: string
    service_type: string
    status: string
    cert_status?: '申请中' | '成功' | '失败' | '无'
    cert_retry_count?: number
    cert_retry_at?: string | null
    tgsend: number
    st_tgsend: number
    site_id?: number | null
    cf_hosted?: number
    cf_account_id?: number | null
    memo: string
    created_at?: string
}

interface ApiResponse<T = any> {
    status: number
    message: string
    data: T
}

// 获取域名列表
export const getDomains = () => {
    return request.get<ApiResponse<DomainData[]>>('/api/domains')
}

// 创建域名
export const createDomain = (data: Omit<DomainData, 'id' | 'created_at'>) => {
    return request.post<ApiResponse<DomainData>>('/api/domains', data)
}

// 更新域名
export const updateDomain = (id: number, data: Omit<DomainData, 'id' | 'created_at'>) => {
    return request.put<ApiResponse<DomainData>>(`/api/domains/${id}`, data)
}

// 删除域名
export const deleteDomain = (id: number) => {
    return request.delete<ApiResponse<void>>(`/api/domains/${id}`)
} 
