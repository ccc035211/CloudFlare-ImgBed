import { errorHandling, telemetryData } from "./utils/middleware";

addEventListener('fetch', (event) => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  if (request.method === 'OPTIONS') {
    // OPTIONS 请求处理
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      },
    });
  }

  // 其他请求处理
  const response = await fetch(request);
  const newHeaders = new Headers(response.headers);
  newHeaders.set('Access-Control-Allow-Origin', '*');
  return new Response(response.body, {
    ...response,
    headers: newHeaders,
  });
}


function UnauthorizedException(reason) {
    return new Response(reason, {
        status: 401,
        statusText: "Unauthorized",
        headers: {
            "Content-Type": "text/plain;charset=UTF-8",
            // Disables caching by default.
            "Cache-Control": "no-store",
            // Returns the "Content-Length" header for HTTP HEAD requests.
            "Content-Length": reason.length,
        },
    });
}

function isValidAuthCode(envAuthCode, authCode) {
    return authCode === envAuthCode;
}

function isAuthCodeDefined(authCode) {
    return authCode !== undefined && authCode !== null && authCode.trim() !== '';
}


function getCookieValue(cookies, name) {
    const match = cookies.match(new RegExp('(^| )' + name + '=([^;]+)'));
    return match ? decodeURIComponent(match[2]) : null;
}

function authCheck(env, url, request) {
    // 优先从请求 URL 获取 authCode
    let authCode = url.searchParams.get('authCode');
    // 如果 URL 中没有 authCode，从 Referer 中获取
    if (!authCode) {
        const referer = request.headers.get('Referer');
        if (referer) {
            try {
                const refererUrl = new URL(referer);
                authCode = new URLSearchParams(refererUrl.search).get('authCode');
            } catch (e) {
                console.error('Invalid referer URL:', e);
            }
        }
    }
    // 如果 Referer 中没有 authCode，从请求头中获取
    if (!authCode) {
        authCode = request.headers.get('authCode');
    }
    // 如果请求头中没有 authCode，从 Cookie 中获取
    if (!authCode) {
        const cookies = request.headers.get('Cookie');
        if (cookies) {
            authCode = getCookieValue(cookies, 'authCode');
        }
    }
    if (isAuthCodeDefined(env.AUTH_CODE) && !isValidAuthCode(env.AUTH_CODE, authCode)) {
        return false;
    }
    return true;
}

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    // 检查 OPTIONS 请求（CORS 预检请求）
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      });
    }

    const url = new URL(request.url);
    const clonedRequest = await request.clone();

    // 鉴权
    if (!authCheck(env, url, request)) {
      return createErrorResponse("Unauthorized", 401);
    }

    // 获得上传 IP
    const uploadIp =
      request.headers.get("cf-connecting-ip") ||
      request.headers.get("x-real-ip") ||
      "unknown";

    // 判断上传 IP 是否被封禁
    const isBlockedIp = await isBlockedUploadIp(env, uploadIp);
    if (isBlockedIp) {
      return createErrorResponse("Your IP is blocked", 403);
    }

    // 检查 KV 数据库配置
    if (!env.img_url) {
      return createErrorResponse("Please configure KV database", 500);
    }

    // 获取上传文件信息
    const formdata = await clonedRequest.formData();
    const file = formdata.get("file");

    // 检查文件的完整性
    if (!file) {
      return createErrorResponse("No file uploaded", 400);
    }
    const fileType = file.type || "unknown";
    const fileName = file.name || "unknown";
    const fileSize = (file.size / 1024 / 1024).toFixed(2); // 单位 MB

    // 构建文件元数据
    const time = Date.now();
    const metadata = {
      FileName: fileName,
      FileType: fileType,
      FileSize: fileSize,
      UploadIP: uploadIp,
      ListType: "None",
      TimeStamp: time,
    };

    // 校验文件扩展名
    let fileExt = fileName.split(".").pop();
    if (!isExtValid(fileExt)) {
      fileExt = fileType.split("/").pop() || "unknown";
    }

    // 构建文件 ID
    const nameType = url.searchParams.get("uploadNameType") || "default";
    const uniqueIndex = time + Math.floor(Math.random() * 10000);
    let fullId = "";
    if (nameType === "index") {
      fullId = `${uniqueIndex}.${fileExt}`;
    } else if (nameType === "origin") {
      fullId = fileName || `${uniqueIndex}.${fileExt}`;
    } else {
      fullId = fileName ? `${uniqueIndex}_${fileName}` : `${uniqueIndex}.${fileExt}`;
    }

    // 构建返回链接
    const returnFormat = url.searchParams.get("returnFormat") || "default";
    const returnLink =
      returnFormat === "full"
        ? `${url.origin}/file/${fullId}`
        : `/file/${fullId}`;

    // 清除 CDN 缓存
    const cdnUrl = `https://${url.hostname}/file/${fullId}`;
    try {
      await purgeCDNCache(env, cdnUrl, url);
    } catch (error) {
      console.error("CDN Cache Purge Error:", error);
    }

    // 处理上传逻辑
    const uploadChannel = url.searchParams.get("uploadChannel") || "telegram";
    const autoRetry = url.searchParams.get("autoRetry") !== "false"; // 默认开启自动重试
    let res;
    let err;

    if (uploadChannel === "cfr2") {
      // Cloudflare R2 渠道
      res = await uploadFileToCloudflareR2(env, formdata, fullId, metadata, returnLink);
      if (res.status !== 200 && autoRetry) {
        err = await res.text();
      }
    } else {
      // Telegram 渠道
      res = await uploadFileToTelegram(env, formdata, fullId, metadata, fileExt, fileName, fileType, url, clonedRequest, returnLink);
      if (res.status !== 200 && autoRetry) {
        err = await res.text();
      }
    }

    // 自动切换渠道重试
    if (err) {
      res = await tryRetry(err, env, uploadChannel, formdata, fullId, metadata, fileExt, fileName, fileType, url, clonedRequest, returnLink);
    }

    return res;
  } catch (error) {
    console.error("Worker Error:", error);
    return createErrorResponse("Internal Server Error", 500);
  }
}

// 辅助函数：创建错误响应
function createErrorResponse(message, status) {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}


// 自动切换渠道重试
async function tryRetry(err, env, uploadChannel, formdata, fullId, metadata, fileExt, fileName, fileType, url, clonedRequest, returnLink) {
    // 渠道列表
    const channelList = ['CloudflareR2', 'TelegramNew'];
    const errMessages = {};
    errMessages[uploadChannel] = 'Error: ' + uploadChannel + err;
    for (let i = 0; i < channelList.length; i++) {
        if (channelList[i] !== uploadChannel) {
            let res = null;
            if (channelList[i] === 'CloudflareR2') {
                res = await uploadFileToCloudflareR2(env, formdata, fullId, metadata, returnLink);
            } else if (channelList[i] === 'TelegramNew') {
                res = await uploadFileToTelegram(env, formdata, fullId, metadata, fileExt, fileName, fileType, url, clonedRequest, returnLink);
            }
            if (res.status === 200) {
                return res;
            } else {
                errMessages[channelList[i]] = 'Error: ' + channelList[i] + await res.text();
            }
        }
    }

    return new Response(JSON.stringify(errMessages), { status: 500 });
}


// 上传到Cloudflare R2
async function uploadFileToCloudflareR2(env, formdata, fullId, metadata, returnLink) {
    // 检查R2数据库是否配置
    if (typeof env.img_r2 == "undefined" || env.img_r2 == null || env.img_r2 == "") {
        return new Response('Error: Please configure R2 database', { status: 500 });
    }
    
    const R2DataBase = env.img_r2;

    // 写入R2数据库
    await R2DataBase.put(fullId, formdata.get('file'));

    // 图像审查
    const R2PublicUrl = env.R2PublicUrl;
    const moderateUrl = `${R2PublicUrl}/${fullId}`;
    metadata = await moderateContent(env, moderateUrl, metadata);

    // 更新metadata，写入KV数据库
    try {
        metadata.Channel = "CloudflareR2";
        await env.img_url.put(fullId, "", {
            metadata: metadata,
        });
    } catch (error) {
        return new Response('Error: Failed to write to KV database', { status: 500 });
    }


    // 成功上传，将文件ID返回给客户端
    return new Response(
        JSON.stringify([{ 'src': `${returnLink}` }]), 
        {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        }
    );
}


// 上传到Telegram
async function uploadFileToTelegram(env, formdata, fullId, metadata, fileExt, fileName, fileType, url, clonedRequest, returnLink) {
    // 由于TG会把gif后缀的文件转为视频，所以需要修改后缀名绕过限制
    if (fileExt === 'gif') {
        const newFileName = fileName.replace(/\.gif$/, '.jpeg');
        const newFile = new File([formdata.get('file')], newFileName, { type: fileType });
        formdata.set('file', newFile);
    } else if (fileExt === 'webp') {
        const newFileName = fileName.replace(/\.webp$/, '.jpeg');
        const newFile = new File([formdata.get('file')], newFileName, { type: fileType });
        formdata.set('file', newFile);
    }

    // 选择对应的发送接口
    const fileTypeMap = {
        'image/': {'url': 'sendPhoto', 'type': 'photo'},
        'video/': {'url': 'sendVideo', 'type': 'video'},
        'audio/': {'url': 'sendAudio', 'type': 'audio'},
        'application/pdf': {'url': 'sendDocument', 'type': 'document'},
    };

    const defaultType = {'url': 'sendDocument', 'type': 'document'};

    let sendFunction = Object.keys(fileTypeMap).find(key => fileType.startsWith(key)) 
        ? fileTypeMap[Object.keys(fileTypeMap).find(key => fileType.startsWith(key))] 
        : defaultType;

    // GIF 发送接口特殊处理
    if (fileType === 'image/gif' || fileType === 'image/webp' || fileExt === 'gif' || fileExt === 'webp') {
        sendFunction = {'url': 'sendAnimation', 'type': 'animation'};
    }

    // 根据服务端压缩设置处理接口：从参数中获取serverCompress，如果为false，则使用sendDocument接口
    if (url.searchParams.get('serverCompress') === 'false') {
        sendFunction = {'url': 'sendDocument', 'type': 'document'};
    }

    // 根据发送接口向表单嵌入chat_id
    let newFormdata = new FormData();
    newFormdata.append('chat_id', env.TG_CHAT_ID);
    newFormdata.append(sendFunction.type, formdata.get('file'));

    
    // 构建目标 URL 
    // const targetUrl = new URL(url.pathname, 'https://telegra.ph'); // telegraph接口，已失效，缅怀
    const targetUrl = new URL(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/${sendFunction.url}`); // telegram接口
    // 目标 URL 剔除 authCode 参数
    url.searchParams.forEach((value, key) => {
        if (key !== 'authCode') {
            targetUrl.searchParams.append(key, value);
        }
    });
    // 复制请求头并剔除 authCode
    const headers = new Headers(clonedRequest.headers);
    headers.delete('authCode');


    // 向目标 URL 发送请求
    let res = new Response('upload error, check your environment params about telegram channel!', { status: 400 });
    try {
        const response = await fetch(targetUrl.href, {
            method: clonedRequest.method,
            headers: {
                "User-Agent": " Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0"
            },
            body: newFormdata,
        });
        const clonedRes = await response.clone().json(); // 等待响应克隆和解析完成
        const fileInfo = getFile(clonedRes);
        const filePath = await getFilePath(env, fileInfo.file_id);
        const id = fileInfo.file_id;
        // 更新FileSize
        metadata.FileSize = (fileInfo.file_size / 1024 / 1024).toFixed(2);

        // 若上传成功，将响应返回给客户端
        if (response.ok) {
            res = new Response(
                JSON.stringify([{ 'src': `${returnLink}` }]),
                {
                    status: 200,
                    headers: { 'Content-Type': 'application/json' }
                }
            );
        }


        // 图像审查
        const moderateUrl = `https://api.telegram.org/file/bot${env.TG_BOT_TOKEN}/${filePath}`;
        metadata = await moderateContent(env, moderateUrl, metadata);

        // 更新metadata，写入KV数据库
        try {
            metadata.Channel = "TelegramNew";
            metadata.TgFileId = id;
            metadata.TgChatId = env.TG_CHAT_ID;
            metadata.TgBotToken = env.TG_BOT_TOKEN;
            await env.img_url.put(fullId, "", {
                metadata: metadata,
            });
        } catch (error) {
            res = new Response('Error: Failed to write to KV database', { status: 500 });
        }
    } catch (error) {
        res = new Response('upload error, check your environment params about telegram channel!', { status: 400 });
    } finally {
        return res;
    }
}


// 图像审查
async function moderateContent(env, url, metadata) {
    const apikey = env.ModerateContentApiKey;
    if (apikey == undefined || apikey == null || apikey == "") {
        metadata.Label = "None";
    } else {
        try {
            const fetchResponse = await fetch(`https://api.moderatecontent.com/moderate/?key=${apikey}&url=${url}`);
            if (!fetchResponse.ok) {
                throw new Error(`HTTP error! status: ${fetchResponse.status}`);
            }
            const moderate_data = await fetchResponse.json();
            metadata.Label = moderate_data.rating_label;
        } catch (error) {
            console.error('Moderate Error:', error);
            // 将不带审查的图片写入数据库
            metadata.Label = "None";
        } finally {
            console.log('Moderate Done');
        }
    }
    return metadata;
}

function getFile(response) {
    try {
		if (!response.ok) {
			return null;
		}

		const getFileDetails = (file) => ({
			file_id: file.file_id,
			file_name: file.file_name || file.file_unique_id,
            file_size: file.file_size,
		});

		if (response.result.photo) {
			const largestPhoto = response.result.photo.reduce((prev, current) =>
				(prev.file_size > current.file_size) ? prev : current
			);
			return getFileDetails(largestPhoto);
		}

		if (response.result.video) {
			return getFileDetails(response.result.video);
		}

        if (response.result.audio) {
            return getFileDetails(response.result.audio);
        }

		if (response.result.document) {
			return getFileDetails(response.result.document);
		}

		return null;
	} catch (error) {
		console.error('Error getting file id:', error.message);
		return null;
	}
}

async function getFilePath(env, file_id) {
    try {
        const url = `https://api.telegram.org/bot${env.TG_BOT_TOKEN}/getFile?file_id=${file_id}`;
        const res = await fetch(url, {
          method: 'GET',
          headers: {
            "User-Agent": " Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome"
          },
        })
    
        let responseData = await res.json();
        if (responseData.ok) {
          const file_path = responseData.result.file_path
          return file_path
        } else {
          return null;
        }
      } catch (error) {
        return null;
      }
}

async function purgeCDNCache(env, cdnUrl, url) {
    const options = {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-Auth-Email': `${env.CF_EMAIL}`, 'X-Auth-Key': `${env.CF_API_KEY}`},
        body: `{"files":["${ cdnUrl }"]}`
    };

    await fetch(`https://api.cloudflare.com/client/v4/zones/${ env.CF_ZONE_ID }/purge_cache`, options);

    // 清除api/randomFileList API缓存
    try {
        const cache = caches.default;
        // await cache.delete(`${url.origin}/api/randomFileList`); delete有bug，通过写入一个max-age=0的response来清除缓存
        const nullResponse = new Response(null, {
            headers: { 'Cache-Control': 'max-age=0' },
        });
        await cache.put(`${url.origin}/api/randomFileList`, nullResponse);
    } catch (error) {
        console.error('Failed to clear cache:', error);
    }
}

function isExtValid(fileExt) {
    return ['jpeg', 'jpg', 'png', 'gif', 'webp', 
    'mp4', 'mp3', 'ogg',
    'mp3', 'wav', 'flac', 'aac', 'opus',
    'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'pdf', 
    'txt', 'md', 'json', 'xml', 'html', 'css', 'js', 'ts', 'go', 'java', 'php', 'py', 'rb', 'sh', 'bat', 'cmd', 'ps1', 'psm1', 'psd', 'ai', 'sketch', 'fig', 'svg', 'eps', 'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'apk', 'exe', 'msi', 'dmg', 'iso', 'torrent', 'webp', 'ico', 'svg', 'ttf', 'otf', 'woff', 'woff2', 'eot', 'apk', 'crx', 'xpi', 'deb', 'rpm', 'jar', 'war', 'ear', 'img', 'iso', 'vdi', 'ova', 'ovf', 'qcow2', 'vmdk', 'vhd', 'vhdx', 'pvm', 'dsk', 'hdd', 'bin', 'cue', 'mds', 'mdf', 'nrg', 'ccd', 'cif', 'c2d', 'daa', 'b6t', 'b5t', 'bwt', 'isz', 'isz', 'cdi', 'flp', 'uif', 'xdi', 'sdi'
    ].includes(fileExt);
}

async function isBlockedUploadIp(env, uploadIp) {
    // 检查是否配置了KV数据库
    if (typeof env.img_url == "undefined" || env.img_url == null || env.img_url == "") {
        return false;
    }

    const kv = env.img_url;
    let list = await kv.get("manage@blockipList");
    if (list == null) {
        list = [];
    } else {
        list = list.split(",");
    }

    return list.includes(uploadIp);
}
