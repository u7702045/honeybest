# HoneyBest LSM

<img src="images/HoneyBest.jpg" width="200" height="250" />

**HoneyBest** 是一個 Linux 安全模組 (LSM)，旨在透過活動式白名單和即時互動機制提供適應性強、使用者友善的安全策略。

*Read this in other languages: [English](README.md), [正體中文](README.zh-tw.md).*

---

## 目錄

- [概述](#概述)
- [背景](#背景)
- [設計理念](#設計理念)
  - [狀況 A：環境複雜性](#狀況-a環境複雜性)
  - [狀況 B：高學習曲線](#狀況-b高學習曲線)
  - [狀況 C：不信任的 root](#狀況-c不信任的-root)
  - [狀況 D：即時互動](#狀況-d即時互動)
  - [狀況 E：雙向保護](#狀況-e雙向保護)
- [架構](#架構)
- [編譯與安裝](#編譯與安裝)
- [配置](#配置)
  - [啟用選項](#啟用選項)
  - [功能選擇](#功能選擇)
  - [鎖定模式](#鎖定模式)
  - [互動模式](#互動模式)
  - [黑名單/白名單模式](#黑名單白名單模式)
  - [粒度等級](#粒度等級)
- [活動配置](#活動配置)
  - [共同欄位](#共同欄位)
  - [活動檔案](#活動檔案)
  - [調整範例](#調整範例)
  - [儲存與還原](#儲存與還原)
- [使用案例](#使用案例)
  - [專屬共享函式庫保護](#專屬共享函式庫保護)
- [授權](#授權)

---

## 概述

HoneyBest 是一個 Linux 安全模組，解決了傳統安全模組（如 SELinux、AppArmor、Smack 和 Tomoyo）的複雜性和可用性挑戰。與需要大量專業知識才能配置的規則式安全模組不同，HoneyBest 採用活動式方法，從觀察到的系統行為自動生成安全策略。

**主要特色：**
- **活動式策略生成**：透過追蹤核心活動自動建立安全策略
- **即時互動**：互動模式允許開發者在活動發生時批准或拒絕新活動
- **低學習曲線**：隱藏規則複雜性，同時允許進階使用者微調粒度
- **雙向保護**：保護資源免受任務存取，同時保護任務免受未授權存取
- **生產就緒**：支援安全啟動整合和硬體信任根綁定

---

## 背景

傳統的 Linux 安全模組已經存在多年，包括 SELinux、AppArmor、Smack 和 Tomoyo。然而，這些解決方案在採用上面臨重大障礙：

- **高進入門檻**：大多數 Linux 使用者缺乏配置複雜規則式安全策略的專業知識
- **後期開發整合**：安全模組通常在軟體開發後才整合，需要安全專家了解每個程序和互動
- **複雜的規則管理**：建立和維護安全規則需要深入理解系統行為和威脅模型

HoneyBest 透過以下方式解決這些挑戰：

1. **自動策略生成**：基於即時系統場景建立安全策略，而非手動建立規則
2. **互動式開發**：支援與開發者即時互動，在安全條件下批准或拒絕活動
3. **規則的替代方案**：提供活動式模型，消除傳統規則概念的需求

---

## 設計理念

HoneyBest 解決安全模組設計中的五個核心挑戰：

### 狀況 A：環境複雜性

**問題**：複雜的環境使安全規則難以正確應用。

**範例情境**：開發團隊完成了一個包含以下服務的 Linux 設備軟體開發：
- NGINX 伺服器用於網頁配置
- Samba 伺服器用於檔案分享
- SNMP 伺服器用於遠端管理
- Syslog 伺服器用於系統日誌

安全專家 Bob 必須了解每個程序、它們如何與系統和其他程序互動，並據此建立規則。例如：
- Syslog 伺服器需要在 `/var/log/*.log` 下建立檔案，僅具有 WRITE 權限
- Syslog 伺服器僅能綁定到 localhost UDP 埠 514 以接收日誌訊息
- Logrotate 守護程序需要權限來移動日誌檔案（DELETE/CREATE/READ/WRITE）
- NGINX 網頁伺服器需要 READ 權限以透過網頁介面顯示日誌內容
- NGINX 還需要權限與 UDP 埠 514 互動以記錄自身訊息

基於此威脅模型建立規則後，系統在整合測試中失敗。調查發現 NGINX 需要與 UDP 埠 514 互動的權限，這一點被遺漏了。

**HoneyBest 解決方案**：HoneyBest 透過在系統整合測試期間自動追蹤活動來適應開發流程，消除了手動映射所有程序互動的需求。

<img src="images/DevelopmentFlow.JPG" width="500" height="220" />

### 狀況 B：高學習曲線

**問題**：使用者、角色、等級、類別、標籤和帽子等安全概念不易理解，需要特定工具和專業知識。

**HoneyBest 解決方案**：HoneyBest 為可能沒有安全專業知識的軟體開發者簡化安全配置，同時仍為需要細粒度控制的進階使用者提供進階功能。

### 狀況 C：不信任的 Root

**問題**：完整的安全策略應將超級使用者（root）視為不受信任。Root 不應被允許更改其他策略，只能更改自己的策略。Root 被入侵可能會破壞所有已建立的安全策略。

**HoneyBest 解決方案**：策略更新和變更與安全啟動過程緊密綁定，特別是與硬體信任根綁定，即使 root 被入侵也能防止未授權的策略修改。

### 狀況 D：即時互動

**問題**：後置應用規則管理是反應式的，難以理解。

**HoneyBest 解決方案**：即時互動回饋機制讓開發者了解即時系統行為。與其使用複雜的規則，互動式對話框解釋活動並請求許可，使安全決策更直觀。進階使用者仍可存取細粒度控制。

### 狀況 E：雙向保護

**問題**：某些情境需要保護任務免受資源存取，同時保護任務免受未授權資源存取。

**範例**：
- 保護專屬函式庫/程式不被盜版，同時仍允許特定程式使用
- 確保只有 "upgrade-firmware" 命令能升級系統韌體（而非 "dd" 命令），並保護 "upgrade-firmware" 命令的完整性

**HoneyBest 解決方案**：HoneyBest 支援限制任務到資源和資源到任務存取的雙向保護模型。

---

## 架構

HoneyBest 的核心設計專注於捕獲由使用者空間程式觸發的核心活動。被追蹤的活動會儲存在列表資料結構中，供安全模組用於偵測意外事件。

**關鍵設計原則：**

1. **活動追蹤**：核心活動被捕獲並轉換為結構化資料
2. **粒度控制**：資料結構的大小取決於所選的粒度等級——更高的粒度提供更精確的控制，但需要更多儲存空間
3. **凍結/解凍模型**：
   - **解凍模式**：系統正常執行，所有活動被追蹤並加入模型
   - **凍結模式**：系統限制所有活動僅限於先前觀察到的模型
4. **互動式精細調整**：開發者可以使用編輯器或互動模式微調模型，在新活動發生時會提示許可

**生命週期工作流程：**

1. 產品開發完成
2. 啟用解凍模式 / 關閉互動模式
3. 執行第一次端對端系統整合測試
4. 關閉解凍模式 / 啟用互動模式
5. 執行第二次端對端系統整合測試或手動編輯模型
6. 關閉互動模式（系統現在已鎖定）

---

## 編譯與安裝

與 SELinux 和 AppArmor 類似，HoneyBest 整合到 Linux 安全模組框架中。要編譯 HoneyBest：

### 必要條件

對於 Debian/Ubuntu 系統，安裝必要的套件：

```bash
apt-get install build-essential libncurses-dev bison flex libssl-dev libelf-dev bc
```

### 編譯步驟

1. **建立 HoneyBest 目錄**：
   ```bash
   mkdir -p [KERNEL_SOURCE]/security/honeybest
   ```

2. **複製原始碼**：
   ```bash
   cd [KERNEL_SOURCE]/security/honeybest
   git clone [repository-url] .
   ```

3. **套用補丁**：
   ```bash
   cd [KERNEL_SOURCE]/security/honeybest
   patch -p1 < Kconfig.patch
   patch -p1 < Makefile.patch
   ```

4. **複製核心配置**：
   ```bash
   cat /boot/config-$(uname -r) > [KERNEL_SOURCE]/.config
   ```

5. **配置核心**：
   ```bash
   cd [KERNEL_SOURCE]
   make menuconfig
   ```
   導航至：**Security options** → **HoneyBest LSM** 並啟用它。

6. **編譯核心**：
   ```bash
   cd [KERNEL_SOURCE]
   make modules bzImage
   ```

7. **安裝核心和模組**：
   ```bash
   sudo make install
   ```

---

## 配置

### 啟用選項

HoneyBest 預設處於**停用/非互動模式**。要啟用：

**選項 1：GRUB 參數**
```bash
# 在 /etc/default/grub 中的 GRUB_CMDLINE_LINUX 加入
hashlock.enabled=1
sudo update-grub
```

**選項 2：Initrd/ramfs 階段**
```bash
echo 1 > /proc/sys/kernel/honeybest/enabled
```

**⚠️ 安全警告**：當使用 `CONFIG_HONEYBEST_PROD=y` 編譯時，基於安全理由，HoneyBest 在啟用後無法停用。GRUB/initrd 映像更新必須與安全啟動驗證過程緊密整合。

啟用後，核心追蹤活動會記錄在 `/proc/honeybest/` 目錄下的不同檔案中。使用標準檔案讀取工具監控進度：

```bash
tail -f /proc/honeybest/binprm
cat /proc/honeybest/files
```

### 功能選擇

HoneyBest 提供多個功能集用於追蹤不同的系統視角。啟用個別功能：

```bash
# 啟用二進位雜湊追蹤
echo 1 > /proc/sys/kernel/honeybest/binprm

# 啟用檔案操作追蹤
echo 1 > /proc/sys/kernel/honeybest/files

# 啟用套接字追蹤
echo 1 > /proc/sys/kernel/honeybest/socket

# 啟用 IPC 追蹤
echo 1 > /proc/sys/kernel/honeybest/ipc

# 啟用 inode 追蹤
echo 1 > /proc/sys/kernel/honeybest/inode

# 啟用路徑追蹤
echo 1 > /proc/sys/kernel/honeybest/path

# 啟用任務追蹤
echo 1 > /proc/sys/kernel/honeybest/tasks

# 啟用超級區塊追蹤
echo 1 > /proc/sys/kernel/honeybest/sb

# 啟用核心模組追蹤
echo 1 > /proc/sys/kernel/honeybest/kmod

# 啟用 ptrace 追蹤
echo 1 > /proc/sys/kernel/honeybest/ptrace
```

有關每個功能的詳細資訊，請參閱[活動檔案](#活動檔案)章節。

### 鎖定模式

鎖定模式僅在啟用選項開啟時生效（預設：關閉）。啟用後，僅允許預期的活動（白名單中的活動）執行。

**啟用鎖定模式**：
```bash
echo 1 > /proc/sys/kernel/honeybest/locking
```

**停用鎖定模式**：
```bash
echo 0 > /proc/sys/kernel/honeybest/locking
```

**注意**：鎖定模式僅在啟用選項處於活動狀態時有效。

### 互動模式

互動模式允許即時批准或拒絕新活動。它僅在啟用模式處於活動狀態時生效。

**模式**：
- **自動模式**（預設）：啟用後立即追蹤所有活動
- **手動模式**：需要 `libhoneybest-notify` 套件（開發中）來提示使用者批准

**啟用互動模式**：
```bash
echo 1 > /proc/sys/kernel/honeybest/interact
```

**停用互動模式**：
```bash
echo 0 > /proc/sys/kernel/honeybest/interact
```

**注意**：互動模式僅在以下情況下有效：
- 啟用選項處於活動狀態
- 鎖定選項已停用

### 黑名單/白名單模式

HoneyBest 支援白名單和黑名單模式：

- **白名單模式**（預設）：通過列表的所有活動預設允許（類似 iptables ACCEPT 策略）
- **黑名單模式**：通過列表的所有活動預設拒絕（類似 iptables REJECT 策略）

**啟用黑名單模式**：
```bash
echo 1 > /proc/sys/kernel/honeybest/bl
```

**啟用白名單模式**：
```bash
echo 0 > /proc/sys/kernel/honeybest/bl
```

### 粒度等級

粒度控制活動比對和追蹤的精確度：

- **等級 0**（預設）：適合大多數使用情況
- **等級 1-2**：更高的精確度，但：
  - 增加比對時間
  - 降低系統靈活性
  - 更高的儲存需求

**設定粒度等級**：
```bash
# 設定為等級 1
echo 1 > /proc/sys/kernel/honeybest/level

# 設定為等級 2
echo 2 > /proc/sys/kernel/honeybest/level

# 重設為預設（等級 0）
echo 0 > /proc/sys/kernel/honeybest/level
```

---

## 活動配置

`/proc/honeybest/` 目錄中的所有檔案追蹤不同的系統行為。每個檔案都共享共同欄位，如下所述。

### 共同欄位

所有活動檔案都包含以下共同欄位：

| 欄位 | 說明 |
|------|------|
| **NO** | 序號。HoneyBest 從較低到較高的數字開始比較活動。 |
| **FUNCTION** | 功能識別，用於識別不同的活動。例如，在 'socket' 類別下，活動標記為 `listen`、`bind`、`accept`、`open`、`setsocketopt` 等。 |
| **USER ID** | 使用者識別，用於參考身份和功能之間的關係。支援正則表達式（數字和 `*` 星號）。 |
| **ACTION** | 比對動作：`A`（接受）或 `R`（拒絕）。預設值取決於黑名單/白名單選項：當黑名單為 0（白名單模式）時附加接受動作；當黑名單為 1（黑名單模式）時附加拒絕動作。 |

### 活動檔案

| 檔案 | 說明 |
|------|------|
| **binprm** | 追蹤可執行檔案路徑名稱、程序 UID，並計算檔案內容雜湊（SHA-1）以保護完整性。 |
| **files** | 追蹤一般檔案操作：`open`、`read`、`write`、`delete`、`rename`。 |
| **inode** | 追蹤 inode 操作：`create`、`delete`、`read`、`update`、`setxattr`、`getxattr`。 |
| **path** | 追蹤所有檔案類型的行為：裝置節點、硬/軟符號連結、目錄、管道、Unix 套接字。 |
| **socket** | 追蹤 TCP/UDP/ICMP 套接字活動，包括埠號。 |
| **task** | 追蹤程序間活動，例如訊號交換。 |
| **sb** | 追蹤超級區塊資訊。`mount`、`umount`、`df` 等活動會記錄在此。由於系統在 `/proc` 中註冊，與 `file` 和 `path` 類別高度相關。 |
| **kmod** | 追蹤 Linux 核心模組活動。核心 `modprobe` 操作會記錄在此。 |
| **ptrace** | 追蹤用於程序除錯和監控的 ptrace 活動。 |
| **ipc** | 追蹤 Linux 程序間通訊活動：共享記憶體、訊息佇列和信號量。 |
| **notify** | 安全模組和使用者空間應用程式之間的通知通道。在互動模式下，意外事件會儲存在此，供使用者空間程式稍後通知使用者。對話框彈出以獲取安全專家批准或拒絕此類活動。**重要**：啟用互動模式時，通過此檔案的所有事件都可能導致記憶體耗盡。因此，在使用者空間程式中設計 READ 排程器至關重要。notify 檔案中的內容會在每次 READ 操作後清除。 |

### 調整範例

此範例示範如何配置 HoneyBest 進行路徑追蹤，這與符號連結建立活動高度相關。

**基本工作流程**：

1. **啟用 HoneyBest LSM**：
   ```bash
   echo 1 > /proc/sys/kernel/honeybest/enabled
   ```

2. **執行系統測試**：
   ```bash
   # 範例：建立符號連結
   ln -s /etc/services /tmp/services
   ```

3. **在調整白名單之前停用 HoneyBest**：
   ```bash
   echo 0 > /proc/sys/kernel/honeybest/enabled
   ```

4. **檢視追蹤的活動**：
   ```bash
   cat /proc/honeybest/path | grep services
   ```

5. **驗證白名單項目**：如果結果顯示：
   ```
   23 0 0 0 0 0 /etc/services /tmp/services
   ```
   這表示白名單已被自動追蹤。

**進階案例：模式比對**

如果您的系統測試涉及 udev 守護程序不斷建立具有模式的新符號檔案（例如，`/dev/usb0`、`/dev/usb1`、... `/dev/usbn` 連結到 `/dev/ttyUSB0`、`/dev/ttyUSB1` 等），您會注意到路徑檔案中有多行與 `/dev/ttyUSB` 相關。使用正則表達式來整合這些項目：

1. **停用 HoneyBest LSM**：
   ```bash
   echo 0 > /proc/sys/kernel/honeybest/enabled
   ```

2. **將內容傾印到檔案**：
   ```bash
   cat /proc/honeybest/path > /etc/hb/path
   ```

3. **檢視內容**（見下方圖 1）

4. **處理檔案**：
   - 移除第一行（標題）和第一欄（序號）
   - 消除所有重複的行
   - 使用正則表達式整合模式（見下方圖 2）
   - 範例：將 `/dev/ttyUSB0`、`/dev/ttyUSB1`、`/dev/ttyUSB2` 替換為 `/dev/ttyUSB*`

5. **重新套用處理後的活動**：
   ```bash
   cat /etc/hb/path > /proc/honeybest/path
   ```

6. **啟用 HoneyBest LSM**：
   ```bash
   echo 1 > /proc/sys/kernel/honeybest/enabled
   ```

**圖 1：範例路徑檔案內容**

| NO | FUNC | UID | MODE | SUID | GUID | DEV | SOURCE PATH | TARGET PATH |
|----|------|-----|------|------|------|-----|-------------|-------------|
| 0 | 23 | 0 | 0 | 0 | 0 | 0 | /dev/usb0 | /dev/ttyUSB0 |
| 1 | 23 | 0 | 0 | 0 | 0 | 0 | /dev/usb0 | /dev/ttyUSB1 |
| 2 | 23 | 0 | 0 | 0 | 0 | 0 | /dev/usb0 | /dev/ttyUSB2 |
| 3 | 20 | 0 | 420 | 0 | 0 | 0 | /etc/resolv.conf.dhclient-new.1115 | /etc/resolv.conf |

**圖 2：使用正則表達式處理後的路徑檔案**

| FUNC | UID | MODE | SUID | GUID | DEV | SOURCE PATH | TARGET PATH |
|------|-----|------|------|------|-----|-------------|-------------|
| 23 | 0 | 0 | 0 | 0 | 0 | /dev/usb0 | /dev/ttyUSB* |
| 20 | 0 | 420 | 0 | 0 | 0 | /etc/resolv.conf.dhclient-new.* | /etc/resolv.conf |

**驗證**：在系統測試期間啟用鎖定模式以驗證結果。如果系統測試失敗，停用鎖定模式並重新執行活動。比較檔案內容將顯示需要加入哪些遺漏的活動。

### 儲存與還原

儲存和還原 HoneyBest LSM 配置很簡單：

**儲存配置**：
```bash
# 儲存二進位雜湊配置
cat /proc/honeybest/binprm > /etc/hb/binprm

# 儲存檔案操作配置
cat /proc/honeybest/files > /etc/hb/files

# 儲存路徑配置
cat /proc/honeybest/path > /etc/hb/path
# ... 對其他功能集重複
```

**⚠️ 重要**：儲存後，您必須處理檔案（移除標題、消除重複、套用正則表達式），如[調整範例](#調整範例)中步驟 6.4 所述。如果未完成此步驟，HoneyBest LSM 將無法正確還原。

**還原配置**：
```bash
# 還原二進位雜湊配置
cat /etc/hb/binprm > /proc/honeybest/binprm

# 還原檔案操作配置
cat /etc/hb/files > /proc/honeybest/files

# ... 對其他功能集重複
```

**完整設定工作流程**：
```bash
# 1. 還原配置
cat /etc/hb/binprm > /proc/honeybest/binprm
cat /etc/hb/files > /proc/honeybest/files
# ... 還原其他功能集

# 2. 啟用功能集
echo 1 > /proc/sys/kernel/honeybest/binprm
echo 1 > /proc/sys/kernel/honeybest/files
# ... 啟用其他功能集

# 3. 鎖定 HoneyBest（防止進一步追蹤）
echo 1 > /proc/sys/kernel/honeybest/locking

# 4. 啟用 HoneyBest
echo 1 > /proc/sys/kernel/honeybest/enabled
```

**自動化**：將還原命令加入 `initrd` 腳本或 `/etc/rc.local`，以便在系統啟動時自動還原配置。

---

## 使用案例

### 專屬共享函式庫保護

此範例示範如何保護專屬共享函式庫，防止被複製或從系統中提取，即使是由 root 使用者。

**受保護的函式庫**：
- `/usr/lib/arm-linux-gnueabihf/libtss2-sys.so.0.0.0`
- `/usr/lib/arm-linux-gnueabihf/libtss2-mu.so.0.0.0`
- `/usr/lib/arm-linux-gnueabihf/libcrypto.so.1.1`
- `/usr/lib/arm-linux-gnueabihf/libtss2-tcti-device.so.0.0.0`

**必要條件**：

1. **安全啟動**：啟用並配置安全啟動以防止核心和 initramfs 被替換
2. **硬體安全模組 (HSM)**：使用 TPM 或 Arm TrustZone，整合到安全啟動過程中
3. **LUKS 加密**：使用 LUKS 重新格式化分割區，並將 LUKS 金鑰綁定到 HSM

**配置步驟**：

1. **使用生產選項重新編譯核心**：
   ```bash
   # 在核心配置中
   CONFIG_HONEYBEST_PROD=y
   ```

2. **將 'files' 功能集配置加入 initramfs**：
   將配置儲存到 initramfs 中的 `/etc/honeybest/files`：
   
   <img src="images/honeybest blacklist files shared libraries protection.JPG" width="1000" height="150" />

3. **將 'binprm' 功能集配置加入 initramfs**：
   將配置儲存到 initramfs 中的 `/etc/honeybest/binprm`：
   
   <img src="images/honeybest blacklist binprm shared libraries protection.JPG" width="1000" height="150" />

4. **將 'sb' 功能集配置加入 initramfs**：
   將配置儲存到 initramfs 中的 `/etc/honeybest/sb`：
   
   <img src="images/honeybest blacklist sb shared libraries protection.JPG" width="700" height="20" />

5. **加入 initramfs 腳本**（`init-top`）在 chroot 到 LUKS 檔案系統之前執行：
   
   <img src="images/honeybest blacklist setup shared libraries protection.JPG" width="700" height="500" />

此配置確保：
- 函式庫無法透過 `scp`、`cp` 或其他檔案操作被複製
- 只有授權的程序可以載入和使用函式庫
- 超級區塊操作受到限制，以防止檔案系統層級的存取
- 所有保護在掛載根檔案系統之前都是活動的

---

## 授權

本軟體依 GNU General Public License 第 2 版條款授權，由自由軟體基金會發布。詳見 [LICENSE](LICENSE) 檔案。

---

## 貢獻

請閱讀 [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) 以了解我們的行為準則。

---

## 支援

如有問題、疑問或貢獻，請參考專案儲存庫或聯繫維護者。
