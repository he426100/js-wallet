import Request from '@/uni_modules/uview-ui/libs/luch-request'

class LotusRpcEngine {
  constructor(config) {
    if (!config)
      throw new Error(
        'Must pass a config object to the LotusRpcEngine constructor.',
      )
    this.apiAddress = config.apiAddress || 'http://127.0.0.1:1234/rpc/v0'
    this.http = new Request({
      header: {
        Accept: '*/*',
        'Content-Type': 'application/json',
      }
    })
    if (config.token) {
      const { token } = config
      this.http.setConfig((config) => { /* config 为默认全局配置*/
        config.header = Object.assign(config.header, { Authorization: `Bearer ${token}` })
        return config
      })
    }
  }

  request(method, ...params) {
    return this.http.post(
      this.apiAddress,
      {
        jsonrpc: '2.0',
        method: `Filecoin.${method}`,
        params,
        id: 1,
      }
    ).then(({ data }) => {
      if (data.error) {
        console.log(data.error)
        throw new Error(data.error.message)
      }
      return data.result
    })
  }
}

module.exports = LotusRpcEngine