<?php
session_start();

/** === OAuth конфиг === */
const B24_PORTAL      = 'example.bitrix24.ru';           
const B24_CLIENT_ID   = 'YOUR_CLIENT_ID';                
const B24_CLIENT_SEC  = 'YOUR_CLIENT_SECRET';            
const B24_REDIRECT    = 'https://example.com/oauth/cb';

function b24_oauth_authorize() {
    $state = bin2hex(random_bytes(16));
    $_SESSION['b24_state'] = $state;
    $authUrl = 'https://' . B24_PORTAL . '/oauth/authorize/?' . http_build_query([
        'client_id'     => B24_CLIENT_ID,
        'response_type' => 'code',
        'redirect_uri'  => B24_REDIRECT,
        'state'         => $state,
    ]);
    header('Location: ' . $authUrl);
    exit;
}

function b24_oauth_token($code) {
    $url = 'https://' . B24_PORTAL . '/oauth/token/';
    $post = [
        'grant_type'   => 'authorization_code',
        'client_id'    => B24_CLIENT_ID,
        'client_secret'=> B24_CLIENT_SEC,
        'code'         => $code,
        'redirect_uri' => B24_REDIRECT,
    ];
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST       => true,
        CURLOPT_POSTFIELDS => $post,
        CURLOPT_RETURNTRANSFER => true,
    ]);
    $resp = curl_exec($ch);
    if ($resp === false) throw new Exception('OAuth token curl error: ' . curl_error($ch));
    $data = json_decode($resp, true);
    if (empty($data['access_token'])) throw new Exception('OAuth token error: ' . $resp);
    return $data; 
}

function b24_oauth_refresh($refreshToken) {
    $url = 'https://oauth.bitrix.info/oauth/token/';
    $post = [
        'grant_type'    => 'refresh_token',
        'client_id'     => B24_CLIENT_ID,
        'client_secret' => B24_CLIENT_SEC,
        'refresh_token' => $refreshToken,
    ];
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST       => true,
        CURLOPT_POSTFIELDS => $post,
        CURLOPT_RETURNTRANSFER => true,
    ]);
    $resp = curl_exec($ch);
    if ($resp === false) throw new Exception('OAuth refresh curl error: ' . curl_error($ch));
    $data = json_decode($resp, true);
    if (empty($data['access_token'])) throw new Exception('OAuth refresh error: ' . $resp);
    return $data;
}

function b24_api($method, $params = []) {
    if (!isset($_SESSION['b24']['access_token'])) throw new Exception('No access token');

    // авто‑рефреш при истечении
    if (time() >= ($_SESSION['b24']['expires_at'] ?? 0) && isset($_SESSION['b24']['refresh_token'])) {
        $new = b24_oauth_refresh($_SESSION['b24']['refresh_token']);
        $_SESSION['b24']['access_token']  = $new['access_token'];
        $_SESSION['b24']['refresh_token'] = $new['refresh_token'] ?? $_SESSION['b24']['refresh_token'];
        $_SESSION['b24']['expires_at']    = time() + (int)($new['expires_in'] ?? 3600) - 60;
    }

    $params['auth'] = $_SESSION['b24']['access_token'];
    $url = 'https://' . B24_PORTAL . '/rest/' . $method . '.json?' . http_build_query($params);

    $resp = file_get_contents($url);
    if ($resp === false) throw new Exception('REST call error');
    $data = json_decode($resp, true);
    if (isset($data['error'])) throw new Exception('REST error: ' . $data['error_description']);
    return $data['result'];
}

/** === OAuth callback === */
if (isset($_GET['oauth']) && $_GET['oauth'] === 'callback') {
    if (empty($_GET['state']) || $_GET['state'] !== ($_SESSION['b24_state'] ?? '')) {
        http_response_code(400);
        exit('Invalid state');
    }
    try {
        $token = b24_oauth_token($_GET['code']);
        $_SESSION['b24'] = [
            'access_token'  => $token['access_token'],
            'refresh_token' => $token['refresh_token'] ?? null,
            'expires_at'    => time() + (int)($token['expires_in'] ?? 3600) - 60,
            'member_id'     => $token['member_id'] ?? null,
            'domain'        => $token['domain'] ?? null,
        ];
        // Получим текущего пользователя
        $me = b24_api('user.current');
        $_SESSION['user'] = [
            'ID'        => (int)$me['ID'],
            'NAME'      => $me['NAME'] ?? '',
            'LAST_NAME' => $me['LAST_NAME'] ?? '',
        ];
        // Уберём тех.параметры из URL
        $clean = preg_replace('~\?.*$~', '', $_SERVER['REQUEST_URI']);
        header('Location: ' . $clean);
        exit;
    } catch (Throwable $e) {
        http_response_code(500);
        exit('OAuth error: ' . htmlspecialchars($e->getMessage()));
    }
}

/** === Если не авторизован — уходим на OAuth === */
if (empty($_SESSION['user']['ID'])) {
    b24_oauth_authorize();
}

// Теперь в сессии есть текущий пользователь:
$currentUid = (int)$_SESSION['user']['ID'];


// === Справочники пользователей и роли ===

// МОП
$managers = [
    1 => 'Manager',
    2 => 'Manager',
    3 => 'Manager',
    4 => 'Manager',
    5 => 'Manager',
    6 => 'Manager',
    7 => 'Manager',
    8 => 'Manager',
    9 => 'Manager',
    10 => 'Manager',
    11 => 'Manager',
    12 => 'Manager',
    13 => 'Manager',
];

$inactiveManagers = [15, 14]; 

$all_ids    = array_keys($managers);                
$visible_ids = array_values(array_diff($all_ids, $inactiveManagers));


// МПБ
$mpbUsers = [
    16 => 'Manager',
    17 => 'Manager',
    18 => 'Manager',
];

$admins = [19, 20, 21]; // кто видит всё

// Массивы ID для проверки прав
$mopUserIds = array_keys($managers);
$mpbUserIds = array_keys($mpbUsers);

// Флаги доступа
$isAdmin = in_array($currentUid, $admins, true);
$isMop   = in_array($currentUid, $mopUserIds, true);
$isMpb   = in_array($currentUid, $mpbUserIds, true);

$canSeeMop = $isAdmin || $isMop;
$canSeeMpb = $isAdmin || $isMpb;

// Полный запрет, если ни к одной вкладке нет доступа
if (!$canSeeMop && !$canSeeMpb) {
    http_response_code(403);
    exit('<div style="padding:20px;color:#b91c1c;font:14px/1.4 sans-serif;">Доступ запрещён</div>');
}


// dashboard.php — вкладки Главная / МПБ
$webhook = 'https://example.invalid/rest/0/REDACTED/';

$all_ids = array_keys($managers);

// === Фильтрация по GET (менеджеры)
$selected = $_GET['mop'] ?? [];
if (!is_array($selected)) $selected = [$selected];
if (in_array('all', $selected, true)) {
    $selected = $visible_ids;
} else {
    $selected = array_map('intval', array_intersect($visible_ids, $selected));
}
if (empty($selected)) $selected = $visible_ids;

$filtered = $selected;               // эти рисуем строками
$nameToId = array_flip($managers);  
// === Дата по умолчанию
$requestDate  = $_GET['date'] ?? date('Y-m-d');
$selectedDate = $requestDate;

// === Период (работает только при mode=today)
$rawPeriodInput = $_GET['period'] ?? '';
[$dateFrom, $dateTo] = normalizePeriod($rawPeriodInput, $selectedDate);
if (trim((string)$rawPeriodInput) !== '') {
    $selectedDate = $dateTo;
}
$periodDisplay = formatPeriodRange($dateFrom, $dateTo);


// === Подключение к БД 
$conn = new mysqli('localhost', 'USERNAME', 'PASSWORD', 'DBNAME');
if ($conn->connect_error) die("Ошибка подключения к БД: " . $conn->connect_error);
$conn->set_charset('utf8mb4');

$dateFromSql = $conn->real_escape_string($dateFrom) . ' 00:00:00';
$dateToSql   = $conn->real_escape_string($dateTo)   . ' 23:59:59';
$monthStartSql = $conn->real_escape_string(date('Y-m-01 00:00:00', strtotime($selectedDate)));
$monthEndSql   = $conn->real_escape_string(date('Y-m-t 23:59:59', strtotime($selectedDate)));

$tzMsk  = new DateTimeZone('Europe/Moscow');
$nowMsk = new DateTime('now', $tzMsk);
$deadline = (new DateTime('today', $tzMsk))->setTime(16, 0, 0);
$isAfterDeadline = ($nowMsk >= $deadline);

// Холод+победители

$winnerStageCounts = array_fill_keys($all_ids, 0);
$coldLeads         = array_fill_keys($all_ids, 0);
$wonPeriodCounts   = array_fill_keys($all_ids, 0);
$wonMonthCounts    = array_fill_keys($all_ids, 0);

$res = $conn->query("
    SELECT manager_id,
           COALESCE(winners_count,0) AS winners_count,
           COALESCE(`count`,0)       AS cold_count
    FROM cold_leads_cache
");
if ($res) while ($row = $res->fetch_assoc()) {
    $uid = (int)$row['manager_id'];
    if (isset($winnerStageCounts[$uid])) {
        $winnerStageCounts[$uid] = (int)$row['winners_count'];
        $coldLeads[$uid]         = (int)$row['cold_count'];
    }
}

// === Режим главной вкладки
$mode = $_GET['mode'] ?? 'today';

// === Звонки 

$callsStats = [];
$sdEsc = $conn->real_escape_string($selectedDate);
$whereCalls = ($mode === 'today')
  ? "call_date BETWEEN '$dateFromSql' AND '$dateToSql'"
  : "call_date BETWEEN '$sdEsc 00:00:00' AND '$sdEsc 23:59:59'";

$sqlCalls = "
  SELECT user_id,
         SUM(CASE WHEN duration >= 90 THEN 1 ELSE 0 END)              AS count_90,
         SUM(CASE WHEN duration >= 90 THEN duration ELSE 0 END)        AS sum_90,
         SUM(duration)                                                 AS sum_all,
         SUM(CASE WHEN duration IS NOT NULL THEN 1 ELSE 0 END)         AS total_calls
  FROM calls
  WHERE $whereCalls
  GROUP BY user_id
";
if ($r = $conn->query($sqlCalls)) {
  while ($row = $r->fetch_assoc()) {
    $id = (int)$row['user_id'];
    $callsStats[$id] = [
      'count_90'    => (int)$row['count_90'],
      'sum_90'      => (int)$row['sum_90'],
      'sum_all'     => (int)$row['sum_all'],
      'total_calls' => (int)$row['total_calls'],
    ];
  }
}



// Инициализация контейнеров
$kvStats     = array_fill_keys($all_ids, 0.0);
$amountStats = array_fill_keys($all_ids, 0.0);
$wonCount    = array_fill_keys($all_ids, 0);
$totalKv     = 0.0;
$totalAmount = 0.0;
$dealsStats  = [];

// ЕДИНЫЙ запрос по МОП
$sqlMop = "
  SELECT
    mop,

    /* В работе (без периода) */
    SUM( (stage_name NOT IN ('Успешно реализованы','Не выдано','Жду документы')
          AND (close_date IS NULL OR close_date='0000-00-00 00:00:00')) )                                        AS inwork_cnt,
    SUM( CASE WHEN (stage_name NOT IN ('Успешно реализованы','Не выдано','Жду документы')
          AND (close_date IS NULL OR close_date='0000-00-00 00:00:00')) THEN amount ELSE 0 END )                 AS inwork_sum,

    /* Заведено за период (mpb_transfer_date) */
    SUM( CASE WHEN mpb_transfer_date BETWEEN '$dateFromSql' AND '$dateToSql' THEN 1 ELSE 0 END )                 AS created_cnt,
    SUM( CASE WHEN mpb_transfer_date BETWEEN '$dateFromSql' AND '$dateToSql' THEN amount ELSE 0 END )            AS created_sum,

    /* Одобрено — все и за период, плюс бейдж на конкретную дату */
    SUM( CASE WHEN stage_name='Одобрено/согласование' THEN 1 ELSE 0 END )                                        AS appr_all_cnt,
    SUM( CASE WHEN stage_name='Одобрено/согласование' THEN amount ELSE 0 END )                                   AS appr_all_sum,
    SUM( CASE WHEN stage_name='Одобрено/согласование'
               AND approved_date BETWEEN '$dateFromSql' AND '$dateToSql' THEN 1 ELSE 0 END )                     AS appr_period_cnt,
    SUM( CASE WHEN stage_name='Одобрено/согласование'
               AND approved_date BETWEEN '$dateFromSql' AND '$dateToSql' THEN amount ELSE 0 END )                AS appr_period_sum,
    SUM( CASE WHEN stage_name='Одобрено/согласование'
               AND DATE(approved_date) = '{$conn->real_escape_string($selectedDate)}' THEN 1 ELSE 0 END )        AS appr_badge_cnt,

    /* Выдано / Не выдано — за период */
    SUM( CASE WHEN stage_name='Успешно реализованы'
               AND close_date BETWEEN '$dateFromSql' AND '$dateToSql' THEN 1 ELSE 0 END )                        AS won_period_cnt,
    SUM( CASE WHEN stage_name='Успешно реализованы'
               AND close_date BETWEEN '$dateFromSql' AND '$dateToSql' THEN amount ELSE 0 END )                   AS won_period_bg,
    SUM( CASE WHEN stage_name='Успешно реализованы'
               AND close_date BETWEEN '$dateFromSql' AND '$dateToSql' THEN kv ELSE 0 END )                       AS won_period_kv,

    SUM( CASE WHEN stage_name='Не выдано'
               AND close_date BETWEEN '$dateFromSql' AND '$dateToSql' THEN 1 ELSE 0 END )                        AS lose_period_cnt,
    SUM( CASE WHEN stage_name='Не выдано'
               AND close_date BETWEEN '$dateFromSql' AND '$dateToSql' THEN amount ELSE 0 END )                   AS lose_period_sum,

    /* Выдано / Не выдано — за МЕСЯЦ selectedDate */
    SUM( CASE WHEN stage_name='Успешно реализованы'
               AND close_date BETWEEN '$monthStartSql' AND '$monthEndSql' THEN 1 ELSE 0 END )                    AS won_month_cnt,
    SUM( CASE WHEN stage_name='Успешно реализованы'
               AND close_date BETWEEN '$monthStartSql' AND '$monthEndSql' THEN amount ELSE 0 END )               AS won_month_bg,
    SUM( CASE WHEN stage_name='Успешно реализованы'
               AND close_date BETWEEN '$monthStartSql' AND '$monthEndSql' THEN kv ELSE 0 END )                   AS won_month_kv,

    SUM( CASE WHEN stage_name='Не выдано'
               AND close_date BETWEEN '$monthStartSql' AND '$monthEndSql' THEN 1 ELSE 0 END )                    AS lose_month_cnt,
    SUM( CASE WHEN stage_name='Не выдано'
               AND close_date BETWEEN '$monthStartSql' AND '$monthEndSql' THEN amount ELSE 0 END )               AS lose_month_sum

  FROM mpb_deals
  GROUP BY mop
";

if ($r = $conn->query($sqlMop)) {
  while ($row = $r->fetch_assoc()) {
    $name = trim((string)$row['mop']);
    if (!isset($nameToId[$name])) continue;
    $id = $nameToId[$name];

    // Базовые
    $dealsStats[$id]['inwork']     = (int)$row['inwork_cnt'];
    $dealsStats[$id]['inwork_sum'] = (float)$row['inwork_sum'];

    // Режимно-зависимые поля
    if ($mode === 'today') {
      // Заведено / Одобрено / Выдано / Потеряно — ЗА ПЕРИОД
      $dealsStats[$id]['today']      = (int)$row['created_cnt'];
      $dealsStats[$id]['today_sum']  = (float)$row['created_sum'];

      $dealsStats[$id]['approved']      = (int)$row['appr_period_cnt'];
      $dealsStats[$id]['approved_sum']  = (float)$row['appr_period_sum'];
      $dealsStats[$id]['approved_today']= (int)$row['appr_period_cnt']; // бейдж = период

      $dealsStats[$id]['won']      = (int)$row['won_period_cnt'];
      $dealsStats[$id]['won_sum']  = (float)$row['won_period_bg'];
      $dealsStats[$id]['lost']     = (int)$row['lose_period_cnt'];
      $dealsStats[$id]['lost_sum'] = (float)$row['lose_period_sum'];

      $kvStats[$id]     = (float)$row['won_period_kv'];
      $amountStats[$id] = (float)$row['won_period_bg'];
    } else {
      // «В работе» режим: одобрено — ВСЕ, выдано/не выдано — ЗА МЕСЯЦ
      $dealsStats[$id]['approved']      = (int)$row['appr_all_cnt'];
      $dealsStats[$id]['approved_sum']  = (float)$row['appr_all_sum'];
      $dealsStats[$id]['approved_today']= (int)$row['appr_badge_cnt']; // бейдж = за выбранный день

      $dealsStats[$id]['inwork']     = (int)$row['inwork_cnt'];
      $dealsStats[$id]['inwork_sum'] = (float)$row['inwork_sum'];

      $dealsStats[$id]['won']      = (int)$row['won_month_cnt'];
      $dealsStats[$id]['won_sum']  = (float)$row['won_month_bg'];
      $dealsStats[$id]['lost']     = (int)$row['lose_month_cnt'];
      $dealsStats[$id]['lost_sum'] = (float)$row['lose_month_sum'];

      $kvStats[$id]     = (float)$row['won_month_kv'];
      $amountStats[$id] = (float)$row['won_month_bg'];
    }

    // Счётчики «выдано за месяц» для бейджей отделов
     $wonMonthCounts[$id]  = (int)$row['won_month_cnt'];
    $wonPeriodCounts[$id] = (int)$row['won_period_cnt'];
 }
}


// Разделение на Прямые и Агентские
$agentIds = [01, 01, 01];
$directManagers = [];
$agentManagers = [];
foreach ($filtered as $id) {
    if (in_array($id, $agentIds)) $agentManagers[] = $id; else $directManagers[] = $id;
}

$lostDirect = 0; $lostAgent = 0; $lostAll = 0;

foreach ($directManagers as $id) {
    $lostDirect += (int)($dealsStats[$id]['lost'] ?? 0);
}
foreach ($agentManagers as $id) {
    $lostAgent += (int)($dealsStats[$id]['lost'] ?? 0);
}
foreach ($filtered as $id) {
    $lostAll += (int)($dealsStats[$id]['lost'] ?? 0);
}

// Счётчик «выдано за месяц» для бейджей в сводках
$wonMap = ($mode === 'today') ? $wonPeriodCounts : $wonMonthCounts;
$directWonCnt = 0;
foreach ($directManagers as $id) $directWonCnt += (int)($wonMap[$id] ?? 0);
$agentWonCnt = 0;
foreach ($agentManagers as $id) $agentWonCnt += (int)($wonMap[$id] ?? 0);
$allWonCnt = 0;
foreach ($filtered as $id) $allWonCnt += (int)($wonMap[$id] ?? 0);


// для рендера строк
$directManagers = [];
$agentManagers  = [];
foreach ($filtered as $id) {
    if (in_array($id, $agentIds, true)) $agentManagers[] = $id;
    else                                $directManagers[] = $id;
}

// для расчёта итогов (включая уволенных)
$calcDirectManagers = [];
$calcAgentManagers  = [];
foreach ($all_ids as $id) {
    if (in_array($id, $agentIds, true)) $calcAgentManagers[] = $id;
    else                                $calcDirectManagers[] = $id;
}



// Агрегация по отделам
function sumCounts(array $ids, array $dealsStats): array {
    $tot = ['inwork'=>0, 'today'=>0, 'approved'=>0, 'approved_today'=>0, 'lost'=>0];
    foreach ($ids as $id) {
        $row = $dealsStats[$id] ?? [];
        $tot['inwork']         += (int)($row['inwork'] ?? $row['inwork_count'] ?? 0);
        $tot['today']          += (int)($row['today'] ?? 0);
        $tot['approved']       += (int)($row['approved'] ?? 0);
        $tot['approved_today'] += (int)($row['approved_today'] ?? 0);
        $tot['lost']           += (int)($row['lost'] ?? 0);
    }
    return $tot;
}

$modeNow = $_GET['mode'] ?? 'today';
$directCounts = sumCounts($directManagers, $dealsStats);
$agentCounts  = sumCounts($agentManagers,  $dealsStats);
$allCounts    = sumCounts($filtered,       $dealsStats);

// === Вкладка МПБ 
$mpbUsers = [
  23 => 'Manager',
  24 => 'Manager',
  25 => 'Manager',
];
$mpbIds = '20,32,62';

$mpb_inwork = [
  23 => ['cnt'=>0,'sum'=>0.0],
  24 => ['cnt'=>0,'sum'=>0.0],
  25 => ['cnt'=>0,'sum'=>0.0],
];

$mpb_created_today = [
  23 => ['cnt'=>0,'sum'=>0.0],
  24 => ['cnt'=>0,'sum'=>0.0],
  25 => ['cnt'=>0,'sum'=>0.0],
];

$mpb_created_all = [
  23 => ['cnt'=>0,'sum'=>0.0],
  24 => ['cnt'=>0,'sum'=>0.0],
  25 => ['cnt'=>0,'sum'=>0.0],
];

$mpb_approved_today = [
  23 => ['cnt'=>0,'sum'=>0.0],
  24 => ['cnt'=>0,'sum'=>0.0],
  25 => ['cnt'=>0,'sum'=>0.0],
];

$mpb_approved_all = [
  23 => ['cnt'=>0,'sum'=>0.0],
  24 => ['cnt'=>0,'sum'=>0.0],
  25 => ['cnt'=>0,'sum'=>0.0],
];

$mpb_won_today = [
  23 => ['cnt'=>0,'bg'=>0.0,'kv'=>0.0],
  24 => ['cnt'=>0,'bg'=>0.0,'kv'=>0.0],
  25 => ['cnt'=>0,'bg'=>0.0,'kv'=>0.0],
];

$mpb_lose_today = [
  23 => ['cnt'=>0,'sum'=>0.0],
  24 => ['cnt'=>0,'sum'=>0.0],
  25 => ['cnt'=>0,'sum'=>0.0],
];

$mpb_won_month = [
  23 => ['cnt'=>0,'bg'=>0.0,'kv'=>0.0],
  24 => ['cnt'=>0,'bg'=>0.0,'kv'=>0.0],
  25 => ['cnt'=>0,'bg'=>0.0,'kv'=>0.0],
];

$mpb_lose_month = [
  23 => ['cnt'=>0,'sum'=>0.0],
  24 => ['cnt'=>0,'sum'=>0.0],
  25 => ['cnt'=>0,'sum'=>0.0],
];

$mpb_inwork = $mpb_created_today = $mpb_created_all = $mpb_approved_today = $mpb_approved_all = [];
$mpb_won_today = $mpb_lose_today = $mpb_won_month = $mpb_lose_month = [];
foreach ([23,24,25] as $id) {
  $mpb_inwork[$id] = $mpb_created_today[$id] = $mpb_created_all[$id] = $mpb_approved_today[$id] = $mpb_approved_all[$id] = ['cnt'=>0,'sum'=>0.0];
  $mpb_won_today[$id] = $mpb_won_month[$id] = ['cnt'=>0,'bg'=>0.0,'kv'=>0.0];
  $mpb_lose_today[$id] = $mpb_lose_month[$id] = ['cnt'=>0,'sum'=>0.0];
}

$sqlMpb = "
  SELECT responsible_id,

    /* В работе (снимок) */
    SUM( (stage_name NOT IN ('Успешно реализованы','Не выдано','Жду документы')
          AND (close_date IS NULL OR close_date='0000-00-00 00:00:00')) )                                    AS inwork_cnt,
    SUM( CASE WHEN (stage_name NOT IN ('Успешно реализованы','Не выдано','Жду документы')
          AND (close_date IS NULL OR close_date='0000-00-00 00:00:00')) THEN amount ELSE 0 END )             AS inwork_sum,

    /* Заведено: период и всего */
    SUM( CASE WHEN mpb_transfer_date BETWEEN '$dateFromSql' AND '$dateToSql' THEN 1 ELSE 0 END )             AS created_period_cnt,
    SUM( CASE WHEN mpb_transfer_date BETWEEN '$dateFromSql' AND '$dateToSql' THEN amount ELSE 0 END )        AS created_period_sum,
    COUNT(*)                                                                                                  AS created_all_cnt,
    SUM(amount)                                                                                               AS created_all_sum,

    /* Одобрено: период и всего */
    SUM( CASE WHEN stage_name='Одобрено/согласование'
               AND approved_date BETWEEN '$dateFromSql' AND '$dateToSql' THEN 1 ELSE 0 END )                 AS appr_period_cnt,
    SUM( CASE WHEN stage_name='Одобрено/согласование'
               AND approved_date BETWEEN '$dateFromSql' AND '$dateToSql' THEN amount ELSE 0 END )            AS appr_period_sum,
    SUM( CASE WHEN stage_name='Одобрено/согласование' THEN 1 ELSE 0 END )                                    AS appr_all_cnt,
    SUM( CASE WHEN stage_name='Одобрено/согласование' THEN amount ELSE 0 END )                               AS appr_all_sum,

    /* Выдано / Не выдано: период */
    SUM( CASE WHEN stage_name='Успешно реализованы'
               AND close_date BETWEEN '$dateFromSql' AND '$dateToSql' THEN 1 ELSE 0 END )                    AS won_period_cnt,
    SUM( CASE WHEN stage_name='Успешно реализованы'
               AND close_date BETWEEN '$dateFromSql' AND '$dateToSql' THEN amount ELSE 0 END )               AS won_period_bg,
    SUM( CASE WHEN stage_name='Успешно реализованы'
               AND close_date BETWEEN '$dateFromSql' AND '$dateToSql' THEN kv ELSE 0 END )                   AS won_period_kv,
    SUM( CASE WHEN stage_name='Не выдано'
               AND close_date BETWEEN '$dateFromSql' AND '$dateToSql' THEN 1 ELSE 0 END )                    AS lose_period_cnt,
    SUM( CASE WHEN stage_name='Не выдано'
               AND close_date BETWEEN '$dateFromSql' AND '$dateToSql' THEN amount ELSE 0 END )               AS lose_period_sum,

    /* Выдано / Не выдано: месяц selectedDate */
    SUM( CASE WHEN stage_name='Успешно реализованы'
               AND close_date BETWEEN '$monthStartSql' AND '$monthEndSql' THEN 1 ELSE 0 END )                AS won_month_cnt,
    SUM( CASE WHEN stage_name='Успешно реализованы'
               AND close_date BETWEEN '$monthStartSql' AND '$monthEndSql' THEN amount ELSE 0 END )           AS won_month_bg,
    SUM( CASE WHEN stage_name='Успешно реализованы'
               AND close_date BETWEEN '$monthStartSql' AND '$monthEndSql' THEN kv ELSE 0 END )               AS won_month_kv,
    SUM( CASE WHEN stage_name='Не выдано'
               AND close_date BETWEEN '$monthStartSql' AND '$monthEndSql' THEN 1 ELSE 0 END )                AS lose_month_cnt,
    SUM( CASE WHEN stage_name='Не выдано'
               AND close_date BETWEEN '$monthStartSql' AND '$monthEndSql' THEN amount ELSE 0 END )           AS lose_month_sum

  FROM mpb_deals
  WHERE responsible_id IN ($mpbIds)
  GROUP BY responsible_id
";

if ($r = $conn->query($sqlMpb)) {
  while ($row = $r->fetch_assoc()) {
    $id = (int)$row['responsible_id'];
    if (!isset($mpb_inwork[$id])) continue;

    $mpb_inwork[$id]         = ['cnt'=>(int)$row['inwork_cnt'],        'sum'=>(float)$row['inwork_sum']];
    $mpb_created_today[$id]  = ['cnt'=>(int)$row['created_period_cnt'],'sum'=>(float)$row['created_period_sum']];
    $mpb_created_all[$id]    = ['cnt'=>(int)$row['created_all_cnt'],   'sum'=>(float)$row['created_all_sum']];
    $mpb_approved_today[$id] = ['cnt'=>(int)$row['appr_period_cnt'],   'sum'=>(float)$row['appr_period_sum']];
    $mpb_approved_all[$id]   = ['cnt'=>(int)$row['appr_all_cnt'],      'sum'=>(float)$row['appr_all_sum']];

    $mpb_won_today[$id]      = ['cnt'=>(int)$row['won_period_cnt'], 'bg'=>(float)$row['won_period_bg'], 'kv'=>(float)$row['won_period_kv']];
    $mpb_lose_today[$id]     = ['cnt'=>(int)$row['lose_period_cnt'],'sum'=>(float)$row['lose_period_sum']];

    $mpb_won_month[$id]      = ['cnt'=>(int)$row['won_month_cnt'], 'bg'=>(float)$row['won_month_bg'], 'kv'=>(float)$row['won_month_kv']];
    $mpb_lose_month[$id]     = ['cnt'=>(int)$row['lose_month_cnt'],'sum'=>(float)$row['lose_month_sum']];
  }
}


// JSON для МПБ без дубликатов ключей
$MPB_JSON = json_encode([
  'users'           => $mpbUsers,
  'inwork'          => $mpb_inwork,
  'created_today'   => $mpb_created_today,
  'created_all'     => $mpb_created_all,
  'approved_today'  => $mpb_approved_today,
  'approved_all'    => $mpb_approved_all,
  'won_today'       => $mpb_won_today,
  'lose_today'      => $mpb_lose_today,
  'won_month'       => $mpb_won_month,
  'lose_month'      => $mpb_lose_month,
], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

// === План 
$totalPlan = 8000000;
$mpbPlan = $totalPlan;

function money_span($number, $decimals = 2) {
    $num = number_format((float)$number, $decimals, ',', ' ');
    return '<span class="money"><span class="money__n">'.$num.'</span><span class="money__r">₽</span></span>';
}

function normalizePeriod($rawPeriod, $defaultDate) {
    $raw = str_ireplace(['–','—'], ' to ', trim((string)$rawPeriod));

    $from = $defaultDate;
    $to   = $defaultDate;

    if ($raw !== '') {
        $parts = array_map('trim', explode('to', $raw));

        $toYmd = static function($value) {
            $time = strtotime($value);
            return $time ? date('Y-m-d', $time) : null;
        };

        if (count($parts) === 2 && $parts[0] !== '' && $parts[1] !== '') {
            $parsedFrom = $toYmd($parts[0]);
            $parsedTo   = $toYmd($parts[1]);
            if ($parsedFrom && $parsedTo) {
                $from = $parsedFrom;
                $to   = $parsedTo;
            }
        } else {
            $single = $toYmd($raw);
            if ($single) {
                $from = $single;
                $to   = $single;
            }
        }

        if (strtotime($from) > strtotime($to)) {
            [$from, $to] = [$to, $from];
        }
    }

    return [$from, $to];
}

function formatPeriodRange($from, $to) {
    return ($from === $to) ? $from : ($from . ' to ' . $to);
}

function renderRow($id, $selected, $managers, $coldLeads, $callsStats, $dealsStats, $kvStats, $amountStats, $modeNow, $dateNow, $periodDisplay) {
    // нужно для победителей/дедлайна
    global $winnerStageCounts, $isAfterDeadline;

    $dataDate    = htmlspecialchars($dateNow, ENT_QUOTES, 'UTF-8');
    $dataMode    = htmlspecialchars($modeNow, ENT_QUOTES, 'UTF-8');
    $dataPeriod  = htmlspecialchars($periodDisplay, ENT_QUOTES, 'UTF-8');
    $managerNameAttr = htmlspecialchars($managers[$id] ?? (string)$id, ENT_QUOTES, 'UTF-8');

    $kvVal = (float)($kvStats[$id] ?? 0.0);
    $highlightRow = ($kvVal >= 1_000_000) ? 'cell-kvbg--ok' : '';

    $kvCellClass = 'deals-col total-cell cell-kvbg';

    ob_start(); ?>
    <tr class="<?= $highlightRow ?>">
        <!-- Менеджер -->
        <td class="manager-col">
            <?= htmlspecialchars($managers[$id] ?? $id) ?>
            <?php if (in_array($id, $selected)): ?>
            <form method="get" style="display:inline;">
                <?php foreach ($selected as $s): if ($s != $id): ?>
                <input type="hidden" name="mop[]" value="<?= $s ?>">
                <?php endif; endforeach; ?>
                <button type="submit" class="manager-remove" title="Убрать из фильтра">
                  <svg class="manager-remove-icon" xmlns="http://www.w3.org/2000/svg"
                        viewBox="0 0 24 24" stroke="currentColor" fill="none" stroke-width="2">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
                  </svg>
                </button>
            </form>
            <?php endif; ?>
        </td>

        <!-- Холод -->
        <td class="<?= ($coldLeads[$id] ?? 0) < 30 ? 'low-cold' : '' ?>">
          <?= $coldLeads[$id] ?? 0 ?>
        </td>

        <!-- Победители  -->
        <?php
          $wins = (int)($winnerStageCounts[$id] ?? 0);
          $winCellClass = ($isAfterDeadline && $wins > 0) ? 'low-cold' : '';
        ?>
        <td class="deals-col text-center deals-open <?= $winCellClass ?>"
            data-type="winners"
            data-manager-id="<?= $id ?>"
            data-manager-name="<?= $managerNameAttr ?>"
            data-mode="<?= $dataMode ?>"
            data-date="<?= $dataDate ?>"
            data-period="<?= $dataPeriod ?>">
          <div style="text-align:center; cursor:pointer;" title="Показать лиды в стадии «Победители/обработать»">
            <?= $wins ?: '—' ?>
          </div>
        </td>

        <!-- Входящие -->
        <td>—</td>

        <!-- Звонки -->
        <td class="col-calls-count">
          <?= ($callsStats[$id]['count_90'] ?? 0) . '/' . ($callsStats[$id]['total_calls'] ?? 0) ?>
        </td>
        <td class="col-calls-duration">
          <?= number_format(($callsStats[$id]['sum_all'] ?? 0) / 60, 1, ',', ' ') ?> мин
        </td>

        <?php
          $count = $modeNow === 'today' ? ($dealsStats[$id]['today'] ?? 0) : ($dealsStats[$id]['inwork'] ?? 0);
          $sum   = $modeNow === 'today' ? ($dealsStats[$id]['today_sum'] ?? 0) : ($dealsStats[$id]['inwork_sum'] ?? 0);
          $lostCount     = (int)($dealsStats[$id]['lost'] ?? 0);
          $lostSum       = (float)($dealsStats[$id]['lost_sum'] ?? 0);
          $approvedCount = (int)($dealsStats[$id]['approved'] ?? 0);
          $approvedSum   = (float)($dealsStats[$id]['approved_sum'] ?? 0);
        ?>

        <!-- Заведено/В работе -->
        <td class="deals-col deals-open"
            data-type="current"
            data-manager-id="<?= $id ?>"
            data-manager-name="<?= $managerNameAttr ?>"
            data-mode="<?= $dataMode ?>"
            data-date="<?= $dataDate ?>"
            data-period="<?= $dataPeriod ?>">
          <div style="text-align:right; cursor:pointer;" title="Показать сделки">
            <?= $count ?><br>
            <small><?= number_format($sum, 0, ',', ' ') ?> ₽</small>
          </div>
        </td>

        <!-- Одобрено -->
        <td class="deals-col deals-open"
            data-type="approved"
            data-manager-id="<?= $id ?>"
            data-manager-name="<?= $managerNameAttr ?>"
            data-mode="<?= $dataMode ?>"
            data-date="<?= $dataDate ?>"
            data-period="<?= $dataPeriod ?>">
          <div style="text-align:right; cursor:pointer;" title="Показать сделки">
            <?= $approvedCount ?><br>
            <small><?= number_format($approvedSum, 0, ',', ' ') ?> ₽</small>
          </div>
        </td>

        <!-- Потерянные -->
        <td class="deals-col deals-open"
            data-type="lose"
            data-manager-id="<?= $id ?>"
            data-manager-name="<?= $managerNameAttr ?>"
            data-mode="<?= $dataMode ?>"
            data-date="<?= $dataDate ?>"
            data-period="<?= $dataPeriod ?>">
          <div style="text-align:right; cursor:pointer;" title="Показать сделки">
            <?= $lostCount ?><br>
            <small><?= number_format($lostSum, 0, ',', ' ') ?> ₽</small>
          </div>
        </td>

        <!-- Факт КВ/БГ -->
       <td class="<?= $kvCellClass ?> deals-open"
           data-type="won"
           data-manager-id="<?= $id ?>"
           data-manager-name="<?= $managerNameAttr ?>"
           data-mode="<?= ($modeNow === 'today' ? 'today' : 'month') ?>"
           data-date="<?= $dataDate ?>"
           data-period="<?= $dataPeriod ?>">

          <div class="kv-line">
            <span class="kv-label">КВ:</span>
            <span class="kv-value"><?= number_format($kvVal, 2, ',', ' ') ?> ₽</span>
          </div>
          <div class="bg-line">
            <span class="bg-label">БГ:</span>
            <span class="bg-value"><?= number_format((float)($amountStats[$id] ?? 0), 2, ',', ' ') ?> ₽</span>
          </div>
        </td>
    </tr>
    <?php
    return ob_get_clean();
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<title>Дашборд</title>

<?php

$hasPeriod = isset($_GET['period']) && trim((string)$_GET['period']) !== '';
$fpDefault = $hasPeriod ? $_GET['period'] : '';

$fpDefault = str_ireplace(['–','—'], ' to ', $fpDefault);
$fpParts = array_map('trim', explode('to', $fpDefault));

$periodStr = str_ireplace(['–','—'], ' to ', trim((string)($_GET['period'] ?? '')));
$parts = array_values(array_filter(array_map('trim', explode('to', $periodStr))));
$ymd = static function($s){ $t=strtotime($s); return $t?date('Y-m-d',$t):null; };
$jsDefault = "[]";
if (count($parts) === 2) {
    $f = $ymd($parts[0]); $t = $ymd($parts[1]);
    if ($f && $t) $jsDefault = "['{$f}','{$t}']";
} elseif (count($parts) === 1) {
    $one = $ymd($parts[0]);
    if ($one) $jsDefault = "['{$one}']";
}
?>

<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
<script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
<script src="https://cdn.jsdelivr.net/npm/flatpickr/dist/l10n/ru.js"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">

<style>
body { font-family: 'Inter', sans-serif !important; font-size: 14px; color: #1a1a1a; margin: 40px; background: #fff; }
table { border-collapse: collapse; width: 100%; margin-top: 20px; background: white; box-shadow: 0 0 0 1px #e5e7eb; border-radius: 6px; overflow: hidden; }
th, td { border: 1px solid #e5e7eb; padding: 10px 12px; text-align: center; vertical-align: middle; font-family: 'Inter', sans-serif; }
th { background-color: #e0f2fe; font-weight: 600; }
td { font-weight: 400; }
tr:hover td { background-color: #d8e3f0; }

.switch-container { display: flex; align-items: center; justify-content: center; gap: 10px; cursor: pointer; }
.switch { width: 42px; height: 20px; background: #ccc; border-radius: 12px; position: relative; transition: background 0.3s; }
.switch::before { content: ''; position: absolute; width: 18px; height: 18px; top: 1px; left: 1px; background: white; border-radius: 50%; transition: transform 0.3s; }
.switch.on { background: #2563eb; }
.switch:not(.on) { background: #e0f2fe; box-shadow: inset 0 0 0 1px #2563eb; }
.switch.on::before { transform: translateX(22px); }
.switch-label-left, .switch-label-right { font-size: 12px; color: #555; user-select: none; }

.dropdown { position: relative; display: inline-block; margin-top: 6px; }
.dropdown-btn { font-size: 12px; padding: 4px 6px; border: none; background: #bae6fd; color: #1e3a8a; cursor: pointer; border-radius: 4px; }
.dropdown-content { display: none; position: absolute; background-color: #fff; border: 1px solid #ccc; z-index: 99; min-width: 180px; max-height: 220px; overflow-y: auto; box-shadow: 0 2px 6px rgba(0,0,0,0.1); margin-top: 4px; }
.dropdown-content div { padding: 8px 12px; cursor: pointer; font-size: 13px; }
.dropdown-content div:hover { background-color: #f1f1f1; }

.cold-header { text-align: center; vertical-align: bottom; padding-top: 6px; padding-bottom: 4px; width: 60px; }
.deals-col { width: 80px; text-align: center; }
.col-win, .col-dash { width: 50px; }
.col-calls-count, .col-calls-duration { width: 90px; }

.manager-col { width: 180px; text-align: left; padding-left: 14px; }
.manager-remove { background: none; border: none; padding: 0; margin-left: 6px; cursor: pointer; display: inline-flex; align-items: center; justify-content: center; transition: background 0.2s; border-radius: 50%; width: 20px; height: 20px; }
.manager-remove-icon { width: 16px; height: 16px; stroke: #9ca3af; transition: stroke 0.2s; }
.manager-remove:hover { background-color: #fee2e2; }
.manager-remove:hover .manager-remove-icon { stroke: #ef4444; }

.table-wrapper { max-height: 650px; overflow-y: auto; position: relative; }
thead th { position: sticky; top: 0; background-color: #e0f2fe; z-index: 10; box-shadow: 0 1px 0 #e5e7eb; }
th.switch-th { position: relative; padding: 10px 12px 32px; }
th .switch-container { position: absolute; bottom: 6px; left: 50%; transform: translateX(-50%); z-index: 11; }

.total-cell { text-align: right; padding: 8px 12px; vertical-align: middle; }
.kv-line, .bg-line { display: flex; justify-content: space-between; min-width: 120px; }
.kv-label, .bg-label { font-size: 11px; color: #6b7280; }
.kv-value { font-weight: 600; font-size: 14px; color: #1f2937; }
.bg-value { font-size: 12px; color: #374151; }

.floating-toggle { position: fixed; top: 8px; left: 0; z-index: 1000; background: #e0f2fe; padding: 6px 10px; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }

.summary-row { background: #fff; font-weight: 500; color: #111827; }
.summary-badges { display: flex; gap: 12px; justify-content: flex-end; align-items: center; font-size: 13px; }
.summary-badge { padding: 4px 8px; border: 1px solid #e5e7eb; border-radius: 6px; background: #f9fafb; }
.summary-badge b { font-weight: 700; }

.tabs { display:flex; gap:8px; margin-bottom:12px; }
.tab-pill { padding:8px 12px; border:1px solid #e5e7eb; border-radius:6px; background:#f9fafb; color:#111827; font-weight:600; cursor:pointer; }
.tab-pill.active { background:#e0f2fe; color:#1e3a8a; border-color:#93c5fd; }
.tab-panel { display:none; }
.tab-panel.active { display:block; }

.mpb-table td:first-child { text-align:left; }
.mpb-summary { background:#f9fafb; font-weight:600; }
.tab-toolbar { display:flex; gap:12px; align-items:center; margin:8px 0 12px; }
.switch-mpb { width:42px; height:20px; border-radius:12px; position:relative; background:#e0f2fe; box-shadow:inset 0 0 0 1px #2563eb; cursor:pointer; }
.switch-mpb::before { content:''; position:absolute; width:18px; height:18px; top:1px; left:1px; background:#fff; border-radius:50%; transition:transform .3s; }
.switch-mpb.on { background:#2563eb; box-shadow:none; }
.switch-mpb.on::before { transform:translateX(22px); }

.flatpickr-calendar { width: 320px !important; font-family: 'Inter', sans-serif; font-size: 13px; border: 1px solid #e5e7eb; border-radius: 8px; box-shadow: 0 4px 16px rgba(0,0,0,0.05); }
.flatpickr-day { width: 26px; height: 26px; line-height: 26px; margin: 1px; font-size: 12px; }
.flatpickr-day:hover { background: #e0f2fe; }
.flatpickr-day.today { border: 1px solid #2563eb; background: #f0f9ff; }
.flatpickr-day.selected { background: #2563eb; color: white; }
.flatpickr-months { background: #f9fafb; border-bottom: 1px solid #e5e7eb; }
.flatpickr-weekday { color: #555; font-weight: 500; font-size: 12px; }
.flatpickr-current-month input.cur-year { font-weight: 600; }
.flatpickr-day.weekend { color: #2563eb; font-weight: 400; font-size: 12px; background-color: #e0f2fe; }
.flatpickr-day.weekend:hover { background-color: #bae6fd; }

.summary-total { background: #e5e7eb; color: #000; font-weight: 600; }
.summary-total td:nth-child(7) div,
.summary-total td:nth-child(8) div { white-space: nowrap; font-size: 12px; line-height: 1.1; }

.deals-col { width: 100px; }

#tab-main .total-cell .kv-line,
#tab-main .total-cell .bg-line { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
#tab-main .total-cell .kv-label,
#tab-main .total-cell .bg-label { font-size: 11px; color: #6b7280; }
#tab-main .total-cell .kv-value { font-size: 14px; font-weight: 600; white-space: nowrap; }
#tab-main .total-cell .bg-value { font-size: 12px; white-space: nowrap; }

.money { display: inline-flex; align-items: baseline; gap: 4px; white-space: nowrap;               
font-variant-numeric: tabular-nums; font-feature-settings: "tnum" 1, "lnum" 1; }
.money__n { line-height: 1; }
.money__r { line-height: 1; font-size: 0.9em; position: relative; top: 0.02em; }

input.date-button { padding: 3px 6px; font-size: 14px; width: 100px; height: 26px; border: 1px solid #e5e7eb; border-radius: 4px; background-color: #f9fafb; color: #111827; text-align: center; box-shadow: 0 1px 2px rgba(0,0,0,0.03); transition: background 0.2s, border 0.2s; -webkit-appearance: none; appearance: none; box-sizing: border-box; }
input.date-button:hover { background-color: #f3f4f6; border-color: #d1d5db; }
.mpb-table { width: 100%; border-collapse: collapse; table-layout: fixed; }
.mpb-table th:nth-child(1),
.mpb-table td:nth-child(1) { width: 240px; } 

.mpb-table th:nth-child(2),
.mpb-table td:nth-child(2) { width: 120px; } 

.mpb-table th:nth-child(3),
.mpb-table td:nth-child(3) { width: 120px; } 

.mpb-table th:nth-child(4),
.mpb-table td:nth-child(4) { width: 120px; } 

.mpb-table th:nth-child(5),
.mpb-table td:nth-child(5) { width: 120px; } 

.mpb-table th:nth-child(6),
.mpb-table td:nth-child(6) { width: 160px; } 

.mpb-table td { text-align: right; vertical-align: middle; }

.mpb-table td:first-child, 
.mpb-table th:first-child { text-align: left;}

.mpb-table td small,
.mpb-table .kv-value,
.mpb-table .bg-value { white-space: nowrap; }

.mpb-table .kv-line,
.mpb-table .bg-line { display: flex; justify-content: flex-end; align-items: center; gap: 8px; }
.mpb-table tfoot td { line-height: 1.2; }

#tab-mpb .kv-line,
#tab-mpb .bg-line { display: grid; grid-template-columns: 32px 1fr; align-items: center; justify-content:end; column-gap: 6px; }

#tab-mpb .kv-label,
#tab-mpb .bg-label { text-align: right; width: 32px; font-size: 11px; color: #6b7280; }

#tab-mpb .kv-value,
#tab-mpb .bg-value { text-align: right; white-space: nowrap; font-weight: 600; font-variant-numeric: 
 tabular-nums; }

tr.cell-kvbg--ok td { background-color: #e6ffed !important; color: #065f46; font-weight: 600; }

tr.cell-kvbg--ok:hover td { background-color: #d7f7dd !important; }
.deals-col { width: 100px; }

#tab-main table { table-layout: fixed; width: 100%; }
html { scrollbar-gutter: stable both-edges; } 

#tab-main td, #tab-main th { white-space: nowrap; }
.summary-badge { display:inline-block; min-width: 100px; text-align:center; }
.deals-open { cursor: pointer; }
td.deals-open:hover { background-color: #eef6ff; }


</style>
</head>
<body>
    <div class="tabs">
      <?php if ($canSeeMop): ?>
        <div class="tab-pill <?= $canSeeMop ? 'active' : '' ?>" data-tab="main">МОП</div>
      <?php endif; ?>
      <?php if ($canSeeMpb): ?>
        <div class="tab-pill <?= !$canSeeMop ? 'active' : '' ?>" data-tab="mpb">МПБ</div>
      <?php endif; ?>
    </div>

<!-- === Главная вкладка === -->
<?php if ($canSeeMop): ?>
  <div id="tab-main" class="tab-panel <?= $canSeeMpb ? '' : 'active' ?>">
      
  <form method="get" style="margin-bottom: 20px;">
    <input
      type="text"
      name="period"
      value="<?= htmlspecialchars($_GET['period'] ?? $selectedDate) ?>"
      class="date-button period-picker"
      readonly
      style="width:220px"
    >
    <?php foreach ($selected as $id): ?><input type="hidden" name="mop[]" value="<?= $id ?>"><?php endforeach; ?>
    <?php if (isset($_GET['mode'])): ?><input type="hidden" name="mode" value="<?= htmlspecialchars($_GET['mode']) ?>"><?php endif; ?>
  </form>
  <div id="floating-toggle" class="switch-container floating-toggle" onclick="toggleMode()" style="display:none">
    <span class="switch-label-left">Заведено</span>
    <div class="switch <?= $mode === 'all' ? 'on' : '' ?>"></div>
    <span class="switch-label-right">В работе</span>
  </div>
  <table>
    <colgroup>
      <col style="width:180px"> <!-- Менеджер -->
      <col style="width:60px">  <!-- Холод -->
      <col style="width:70px">  <!-- Победители -->
      <col style="width:70px">  <!-- Входящие -->
      <col style="width:90px">  <!-- ≥ 90 сек -->
      <col style="width:100px"> <!-- Длительность -->
      <col style="width:120px"> <!-- Текущие / Заведено/В работе -->
      <col style="width:120px"> <!-- Одобрено -->
      <col style="width:120px"> <!-- Потерянные -->
      <col style="width:170px"> <!-- Факт КВ/БГ -->
    </colgroup>
    <thead>
      <tr>
        <th rowspan="2" class="manager-col" style="position: relative;" id="managerDropdown">
          Менеджер
          <div class="dropdown">
            <div class="dropdown-btn" onclick="toggleDropdown()">Выбрать ▼</div>
            <div class="dropdown-content" id="dropdownContent">
              <?php if (count($selected) !== count($all_ids)): ?>
                <div onclick="selectAllManagers()" style="font-weight: 600; color: #2563eb;">Сбросить фильтр</div>
                <hr style="margin: 5px 0;">
              <?php endif; ?>
              <?php
              $isAllSelected = count($selected) === count($all_ids);
              foreach ($managers as $id => $name):
                if ($isAllSelected || !in_array($id, $selected)):
              ?>
                <div onclick="<?= $isAllSelected ? "selectOnlyManager" : "addManager" ?>('<?= $id ?>')">
                  <?= htmlspecialchars($name) ?>
                </div>
              <?php endif; endforeach; ?>      
            </div>
          </div>
        </th>
        <th colspan="3">Лиды</th>
        <th colspan="2">Звонки</th>
        <th colspan="3">
          <div id="header-toggle" class="switch-container" onclick="toggleMode()" title="Переключить Заведено / В работе">
            <span class="switch-label-left">Заведено</span>
            <div class="switch <?= $mode === 'all' ? 'on' : '' ?>"></div>
            <span class="switch-label-right">В работе</span>
          </div>
        </th>
        <th rowspan="2">Факт КВ/БГ</th>
      </tr>
      <tr>
        <th class="cold-header" style="vertical-align: middle;">Холод</th>
        <th class="col-win">Победители</th>
        <th class="col-dash">Входящие</th>
        <th class="col-calls-count">≥ 90 сек</th>
        <th class="col-calls-duration">Длительность</th>
        <th>Текущие</th>
        <th>Одобрено</th>
        <th>Потерянные</th>
      </tr>
    </thead>
    <tbody>
        <tr>
          <td colspan="10" style="font-weight:bold; background:#fff7ed; text-align:center;">
            Прямые продажи
          </td>
        </tr>
        <?php
        foreach ($directManagers as $id) {
            echo renderRow($id, $selected, $managers, $coldLeads, $callsStats, $dealsStats, $kvStats, $amountStats, $mode, $requestDate, $periodDisplay);
        }
        $modeNow = $_GET['mode'] ?? 'today';
        ?>

        <tr class="summary-row">
          <td colspan="6"></td>
          <td style="text-align:center">
            <span class="summary-badge"><?= ($modeNow==='all') ? 'В работе' : 'Заведено' ?>:
              <b><?= ($modeNow==='all') ? $directCounts['inwork'] : $directCounts['today'] ?></b>
            </span>
          </td>
          <td style="text-align:center">
            <span class="summary-badge">Одобрено: <b><?= $directCounts['approved'] ?></b></span>
          </td>
          <td style="text-align:center">
            <span class="summary-badge">Потеряно: <b><?= (int)$lostDirect ?></b></span>
          </td>
          <td style="text-align:center">
            <span class="summary-badge">Успешно: <b><?= $directWonCnt ?></b></span>
          </td>
        </tr>

        <?php
        $directAmountSum    = 0;  
        $directApprovedAmount = 0;
        $directLostAmount     = 0;
        $directKvSum          = 0; 
        $directBgFactSum      = 0; 

        foreach ($calcDirectManagers as $id) {
            $directKvSum       += $kvStats[$id] ?? 0;
            $directBgFactSum   += $amountStats[$id] ?? 0;
            $directAmountSum   += ($modeNow === 'today')
                ? ($dealsStats[$id]['today_sum']   ?? 0)
                : ($dealsStats[$id]['inwork_sum']  ?? 0);
            $directLostAmount     += $dealsStats[$id]['lost_sum']     ?? 0;
            $directApprovedAmount += $dealsStats[$id]['approved_sum'] ?? 0;
        }
        ?>

        <tr class="summary-total">
          <td colspan="6" style="text-align:right;">ИТОГО:</td>
          <td><div style="text-align:right;"><?= money_span($directAmountSum, 2, ',', ' ') ?></div></td>
          <td><div style="text-align:right;"><?= money_span($directApprovedAmount, 2, ',', ' ') ?></div></td>
          <td><div style="text-align:right;"><?= money_span($directLostAmount, 2, ',', ' ') ?></div></td>
          <td class="total-cell">
            <div class="kv-line"><span class="kv-label">КВ:</span><span class="kv-value"><?= money_span($directKvSum, 2, ',', ' ') ?></span></div>
            <div class="bg-line"><span class="bg-label">БГ:</span><span class="bg-value"><?= money_span($directBgFactSum, 2, ',', ' ') ?></span></div>
          </td>
        </tr>

      <!-- Заголовок для агентских -->
     <tr>
       <td colspan="10" style="font-weight:bold; background:#fff7ed; text-align:center;">
         Агентские продажи
       </td>
     </tr>
     <?php
     // 3.1 РЕНДЕР СТРОК: только видимых агентов
     foreach ($agentManagers as $id) {
        echo renderRow($id, $selected, $managers, $coldLeads, $callsStats, $dealsStats, $kvStats, $amountStats, $mode, $requestDate, $periodDisplay);
     }
     ?>

     <tr class="summary-row">
       <td colspan="6"></td>
       <td style="text-align:center">
         <span class="summary-badge">
           <?= ($modeNow==='all') ? 'В работе' : 'Заведено' ?>:
           <b><?= ($modeNow==='all') ? $agentCounts['inwork'] : $agentCounts['today'] ?></b>
         </span>
       </td>
       <td style="text-align:center">
         <span class="summary-badge">Одобрено: <b><?= $agentCounts['approved'] ?></b></span>
       </td>
       <td style="text-align:center">
         <span class="summary-badge">Потеряно: <b><?= (int)$lostAgent ?></b></span>
       </td>
       <td style="text-align:center">
         <span class="summary-badge">Успешно: <b><?= $agentWonCnt ?></b></span>
       </td>
     </tr>

     <?php
     $agentAmountSum      = 0;
     $agentApprovedAmount = 0;
     $agentLostAmount     = 0;
     $agentKvSum          = 0;
     $agentBgFactSum      = 0;

     foreach ($calcAgentManagers as $id) {
         $agentKvSum       += $kvStats[$id] ?? 0;
         $agentBgFactSum   += $amountStats[$id] ?? 0;
         $agentAmountSum   += ($modeNow === 'today')
             ? ($dealsStats[$id]['today_sum']   ?? 0)
             : ($dealsStats[$id]['inwork_sum']  ?? 0);
         $agentLostAmount     += $dealsStats[$id]['lost_sum']     ?? 0;
         $agentApprovedAmount += $dealsStats[$id]['approved_sum'] ?? 0;
     }
     ?>

     <tr class="summary-total">
       <td colspan="6" style="text-align:right;">ИТОГО:</td>
       <td><div style="text-align:right;"><?= money_span($agentAmountSum, 2, ',', ' ') ?></div></td>
       <td><div style="text-align:right;"><?= money_span($agentApprovedAmount, 2, ',', ' ') ?></div></td>
       <td><div style="text-align:right;"><?= money_span($agentLostAmount, 2, ',', ' ') ?></div></td>
       <td class="total-cell">
         <div class="kv-line"><span class="kv-label">КВ:</span><span class="kv-value"><?= money_span($agentKvSum, 2, ',', ' ') ?></span></div>
         <div class="bg-line"><span class="bg-label">БГ:</span><span class="bg-value"><?= money_span($agentBgFactSum, 2, ',', ' ') ?></span></div>
       </td>
     </tr>


      <?php
        $label = ($modeNow === 'all') ? 'В работе' : 'Заведено';
      ?>
      <tr class="summary-row">
        <td colspan="6"></td>
        <td style="text-align:center">
          <span class="summary-badge">
            <?= $label ?>: <b><?= ($modeNow==='all') ? $allCounts['inwork'] : $allCounts['today'] ?></b>
          </span>
        </td>
        <td style="text-align:center">
          <span class="summary-badge">Одобрено: <b><?= $allCounts['approved'] ?></b></span>
        </td>
        <td style="text-align:center">
          <span class="summary-badge">Потеряно: <b><?= (int)$lostAll ?></b></span>
        </td>
        <td style="text-align:center">
          <span class="summary-badge">Успешно: <b><?= $allWonCnt ?></b></span>
        </td>
      </tr>

<?php
    $sumInwork = 0; $sumApproved = 0; $sumLost = 0;
    foreach ($filtered as $id) {
        $sumInwork   += ($modeNow === 'today') ? ($dealsStats[$id]['today_sum'] ?? 0) : ($dealsStats[$id]['inwork_sum'] ?? 0);
        $sumApproved += $dealsStats[$id]['approved_sum'] ?? 0;
        $sumLost     += $dealsStats[$id]['lost_sum'] ?? 0;
    }
      $sumKv = 0; 
      $sumBg = 0;
      foreach ($all_ids as $mid) {
          $sumKv += $kvStats[$mid] ?? 0;
          $sumBg += $amountStats[$mid] ?? 0;
      }
      ?>
      <tr style="background:#f9fafb; font-weight:bold;">
        <td colspan="6"></td>
        <td><div style="text-align:right;"><?= money_span($sumInwork, 2, ',', ' ') ?> </div></td>
        <td><div style="text-align:right;"><?= money_span($sumApproved, 2, ',', ' ') ?> </div></td>
        <td><div style="text-align:right;"><?= money_span($sumLost, 2, ',', ' ') ?> </div></td>
        <td class="total-cell">
            <div class="kv-line">
                <span class="kv-label">КВ:</span>
                <span class="kv-value"><?= money_span($sumKv, 2, ',', ' ') ?> </span>
            </div>
            <div class="bg-line">
                <span class="bg-label">БГ:</span>
                <span class="bg-value"><?= money_span($sumBg, 2, ',', ' ') ?> </span>
            </div>
        </td>
      </tr>
      <tr style="background:#f9fafb; font-weight:bold;">
        <td colspan="9" style="text-align:right;">План:</td>
        <td class="total-cell">
          <span class="kv-value" style="font-weight:700;"><?= number_format($totalPlan, 2, ',', ' ') ?> ₽</span>
        </td>
      </tr>
      </tr>
    </tbody>
  </table>
</div>
<?php endif; ?>
<!-- === Вкладка МПБ === -->
<?php if ($canSeeMpb): ?>
  <div id="tab-mpb" class="tab-panel <?= $canSeeMop ? '' : 'active' ?>">
  <!-- Жёлтый заголовок -->
  <div class="tab-toolbar">
    <form method="get">
      <input
        type="text"
        name="period"
        value="<?= htmlspecialchars($_GET['period'] ?? $selectedDate) ?>"
        class="date-button period-picker"
        readonly
        style="width:220px"
      >
      <?php foreach ($selected as $id): ?><input type="hidden" name="mop[]" value="<?= $id ?>"><?php endforeach; ?>
      <?php if (isset($_GET['mode'])): ?><input type="hidden" name="mode" value="<?= htmlspecialchars($_GET['mode']) ?>"><?php endif; ?>
    </form>
</div> 
  <div class="table-wrapper" style="margin-top:10px;">
    <table class="mpb-table">
      <thead>
        <tr>
          <th style="width:240px;text-align:left;">ФИО сотрудника</th>
          <th>
            <div style="display:flex;align-items:center;gap:8px;justify-content:center;">
              <span style="font-size:12px;color:#555;">Заведено</span>
              <div id="mpbSwitchZ" class="switch-mpb" title="Переключить Заведено / В работе"></div>
              <span style="font-size:12px;color:#555;">В работе</span>
            </div>
            <small id="hdrCreated" style="display:none;">сегодня</small>
          </th>
          <th>Одобрено<br><small id="hdrApproved" style="display:none;">сегодня</small></th>
          <th>Выдано<br><small id="hdrWon" style="display:none;">сегодня</small></th>
          <th>Не выдано<br><small id="hdrLose" style="display:none;">сегодня</small></th>
          <th>Факт КВ/БГ</th>
        </tr>
      </thead>
      <tr>
         <td colspan="6" style="font-weight:bold; background:#fff7ed; text-align:center;">
           Менеджеры по банкам
         </td>
       </tr>
      <tbody id="mpbBody"></tbody>
      <tfoot>
        <tr class="summary-total">
          <td style="text-align:right;">ИТОГО:</td>
          <td id="totCreated">0<br><small>0 ₽</small></td>
          <td id="totApproved">0<br><small>0 ₽</small></td>
          <td id="totWon">0<br><small>0 ₽</small></td>
          <td id="totLose">0<br><small>0 ₽</small></td>
          <td id="totKv">
            <div class="kv-line"><span class="kv-label">КВ:</span> <span class="kv-value">0 ₽</span></div>
            <div class="bg-line"><span class="bg-label">БГ:</span> <span class="bg-value">0 ₽</span></div>
          </td>
        </tr>
        <tr class="summary-row">
          <td colspan="5" style="text-align:right;">План:</td>
          <td class="total-cell">
            <div class="kv-line"><span class="kv-label">КВ:</span> <span class="kv-value"><?= number_format($totalPlan, 2, ',', ' ') ?> ₽</span></div>
          </td>
        </tr>
      </tfoot>
    </table>
  </div>
</div>
<?php endif; ?>
<!-- Modal -->
<div id="dealModal" style="display:none; position:fixed; inset:0; background:rgba(0,0,0,.35); align-items:center; justify-content:center; z-index:2000;">
  <div style="background:#fff; width:1100px; max-width:96vw; border-radius:10px; box-shadow:0 10px 40px rgba(0,0,0,.2); overflow:hidden;">
    <div style="padding:14px 18px; border-bottom:1px solid #e5e7eb; display:flex; gap:8px; justify-content:space-between; align-items:center;">
      <div id="modalTitle" style="font-weight:600; font-size:16px;">Сделки</div>
      <button onclick="closeModal()" style="border:none;background:none;font-size:20px;cursor:pointer;line-height:1;" type="button">×</button>
    </div>
    <div id="modalBody" style="max-height:72vh; overflow:auto; padding:18px 20px;">
      <div style="padding:16px; font:14px Inter,system-ui;">Загрузка…</div>
    </div>
  </div>
</div>

<script>
// ====== Менеджеры фильтр (главная)
function toggleDropdown() {
    const content = document.getElementById("dropdownContent");
    content.style.display = content.style.display === "block" ? "none" : "block";
}
function selectAllManagers() {
    const url = new URL(window.location.href);
    url.search = '';
    url.searchParams.append("mop[]", "all");
    window.location.href = url.toString();
}
function addManager(id) {
    const url = new URL(window.location.href);
    const params = url.searchParams;
    const newParams = [];
    for (const [key, value] of params.entries()) {
        if (!(key === "mop[]" && value === "all")) newParams.push([key, value]);
    }
    url.search = '';
    newParams.forEach(([k, v]) => url.searchParams.append(k, v));
    url.searchParams.append("mop[]", id);
    window.location.href = url.toString();
}
function selectOnlyManager(id) {
    const url = new URL(window.location.href);
    url.search = '';
    url.searchParams.append("mop[]", id);
    window.location.href = url.toString();
}
document.addEventListener('click', function(event) {
    const dropdown = document.getElementById("managerDropdown");
    const content = document.getElementById("dropdownContent");
    if (dropdown && content && !dropdown.contains(event.target)) content.style.display = "none";
});

// Главный тумблер (главная вкладка)
function toggleMode() {
  const url = new URL(window.location.href);
  const currentMode = url.searchParams.get('mode') || 'today';
  const newMode = currentMode === 'today' ? 'all' : 'today';

  if (newMode === 'all') {
    const period = url.searchParams.get('period') || '';
    let anchor = null;
    if (period) {
      const norm = period.replace(/[–—]/g, ' to ');
      const parts = norm.split('to').map(s => s.trim()).filter(Boolean);
      if (parts.length === 2) anchor = parts[1];  
      else if (parts.length === 1) anchor = parts[0];
    }
    if (anchor) url.searchParams.set('date', anchor);
    url.searchParams.delete('period');
  } else {
    if (!url.searchParams.get('period')) {
      url.searchParams.set('period', "<?= date('Y-m-d') ?>");
    }
  }

  url.searchParams.set('mode', newMode);
  window.location.href = url.toString();
}

(function initPeriodPickers(){
  function fmt(d){
    const y=d.getFullYear(), m=String(d.getMonth()+1).padStart(2,'0'), day=String(d.getDate()).padStart(2,'0');
    return `${y}-${m}-${day}`;
  }
  function applyPeriod(value){
    const url = new URL(window.location.href);
    url.searchParams.set('period', value);
    url.searchParams.set('mode', 'today');
    window.location.href = url.toString();
  }

  document.querySelectorAll('.period-picker').forEach(function(input){
    let startPicked = false;
    let locked = false;

    const fp = flatpickr(input, {
      locale: "ru",
      dateFormat: "Y-m-d",
      mode: "range",
      defaultDate: <?= $jsDefault ?>,
      rangeSeparator: " to ",
      closeOnSelect: false,
      clickOpens: true,
      allowInput: false,

      onOpen(){
        const url = new URL(location.href);
        const hasPeriod = url.searchParams.get('period')?.trim();
        if (!hasPeriod) {
          this.clear();               
          this.setDate([], true);    
        }
        startPicked = false;
        locked = false;
      },

      onDayCreate(dObj, dStr, fp, dayElem){
        const date = dayElem.dateObj;
        if (date.getDay()===0 || date.getDay()===6) dayElem.classList.add("weekend");
        dayElem.addEventListener('dblclick', () => {
          if (locked) return;
          locked = true;
          applyPeriod(fmt(date));
        });
      },

      onChange(selectedDates){
        if (locked) return;

        if (selectedDates.length === 1){
          startPicked = true;
          return;
        }
        if (selectedDates.length === 2 && startPicked){
          locked = true;
          const value = `${fmt(selectedDates[0])} to ${fmt(selectedDates[1])}`;
          applyPeriod(value);
        }
      }
    });
  });
})();

window.addEventListener('beforeunload', () => { localStorage.setItem('scrollY', window.scrollY); });
window.addEventListener('load', () => {
  const y = localStorage.getItem('scrollY');
  if (y) { window.scrollTo(0, parseInt(y)); localStorage.removeItem('scrollY'); }
});

(function() {
  const floating = document.getElementById('floating-toggle');
  const headerEl = document.getElementById('header-toggle');

  function alignFloating() {
    if (!floating || !headerEl) return;
    const rect = headerEl.getBoundingClientRect();
    const pageLeft = window.scrollX || document.documentElement.scrollLeft || 0;
    floating.style.left = (rect.left + pageLeft) + 'px';
    floating.style.width = rect.width + 'px'; //
  }


  function onScroll() {
    if (!floating) return;
    const show = window.scrollY > 100;
    if (show) alignFloating();
    floating.style.display = show ? 'flex' : 'none';
  }

  window.addEventListener('load',  () => { alignFloating(); onScroll(); });
  window.addEventListener('resize', alignFloating, { passive: true });
  window.addEventListener('scroll', onScroll,      { passive: true });
})();


// ====== ДАННЫЕ из PHP для МПБ ======
const MPB = <?= $MPB_JSON ?>; 

const HAS_PERIOD    = <?= $rawPeriod !== '' ? 'true' : 'false' ?>;
const SELECTED_DATE = "<?= htmlspecialchars($selectedDate, ENT_QUOTES, 'UTF-8') ?>";

let mpbMode = 'created';
const mpbSwitchZ = document.getElementById('mpbSwitchZ');
const hdrCreated  = document.getElementById('hdrCreated');
const hdrApproved = document.getElementById('hdrApproved');
const hdrWon  = document.getElementById('hdrWon');
const hdrLose = document.getElementById('hdrLose');

function fmtInt(n){ return (Number(n) || 0).toLocaleString('ru-RU'); }
function fmtRub(n){
  const v = Number(n);
  return (isFinite(v) ? v : 0).toLocaleString('ru-RU', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2
  }) + ' ₽';
}
function cell(count, sum){ return `${fmtInt(count)}<br><small>${fmtRub(sum)}</small>`; }

function renderMPB(){
  const body = document.getElementById('mpbBody');
  const order = [20,32,62];

  // Подписи
  hdrCreated.textContent  = (mpbMode==='created') ? (HAS_PERIOD?'период':'сегодня') : 'в работе';
  hdrApproved.textContent = (mpbMode==='created') ? (HAS_PERIOD?'период':'сегодня') : 'всего';
  hdrWon.textContent      = (mpbMode==='created') ? (HAS_PERIOD?'период':'сегодня') : 'месяц';
  hdrLose.textContent     = (mpbMode==='created') ? (HAS_PERIOD?'период':'сегодня') : 'месяц';

  let totCreatedCnt=0, totCreatedSum=0, totApprCnt=0, totApprSum=0, totWonCnt=0, totWonBg=0, totWonKv=0, totLoseCnt=0, totLoseSum=0, totFactKv=0, totFactBg=0;

  const rows = order.map((id)=>{
    const name = MPB.users[id] || id;

    const createdOrWork = (mpbMode==='created') ? (MPB.created_today[id]||{cnt:0,sum:0}) : (MPB.inwork[id]||{cnt:0,sum:0});
    const approved      = (mpbMode==='created') ? (MPB.approved_today[id]||{cnt:0,sum:0}) : (MPB.approved_all[id]||{cnt:0,sum:0});
    const won           = (mpbMode==='created') ? (MPB.won_today[id]||{cnt:0,bg:0,kv:0})   : (MPB.won_month[id]||{cnt:0,bg:0,kv:0});
    const lose          = (mpbMode==='created') ? (MPB.lose_today[id]||{cnt:0,sum:0})       : (MPB.lose_month[id]||{cnt:0,sum:0});
    const fact          = (mpbMode==='created') ? (MPB.won_today[id]||{cnt:0,bg:0,kv:0})    : (MPB.won_month[id]||{cnt:0,bg:0,kv:0});

    totCreatedCnt+=createdOrWork.cnt; totCreatedSum+=createdOrWork.sum;
    totApprCnt+=approved.cnt;         totApprSum+=approved.sum;
    totWonCnt+=won.cnt;               totWonBg+=won.bg; totWonKv+=won.kv;
    totLoseCnt+=lose.cnt;             totLoseSum+=lose.sum;
    totFactKv+=fact.kv;               totFactBg+=fact.bg;

    const nameAttr = String(name).replace(/"/g,'&quot;');
    const modeForCreatedApproved = (mpbMode==='created') ? 'today' : 'all';
    const modeForWonLose         = (mpbMode==='created') ? 'today' : 'month';

    return `
      <tr>
        <td style="text-align:left;">${name}</td>
        <td class="deals-open" data-section="mpb" data-type="current"  data-manager-id="${id}" data-manager-name="${nameAttr}" data-mode="${modeForCreatedApproved}" data-date="${SELECTED_DATE}">${fmtInt(createdOrWork.cnt)}<br><small>${fmtRub(createdOrWork.sum)}</small></td>
        <td class="deals-open" data-section="mpb" data-type="approved" data-manager-id="${id}" data-manager-name="${nameAttr}" data-mode="${modeForCreatedApproved}" data-date="${SELECTED_DATE}">${fmtInt(approved.cnt)}<br><small>${fmtRub(approved.sum)}</small></td>
        <td class="deals-open" data-section="mpb" data-type="won"      data-manager-id="${id}" data-manager-name="${nameAttr}" data-mode="${modeForWonLose}"        data-date="${SELECTED_DATE}">${fmtInt(won.cnt)}<br><small>${fmtRub(won.bg)}</small></td>
        <td class="deals-open" data-section="mpb" data-type="lose"     data-manager-id="${id}" data-manager-name="${nameAttr}" data-mode="${modeForWonLose}"        data-date="${SELECTED_DATE}">${fmtInt(lose.cnt)}<br><small>${fmtRub(lose.sum)}</small></td>
        <td>
          <div class="kv-line"><span class="kv-label">КВ:</span> <span class="kv-value">${fmtRub(fact.kv)}</span></div>
          <div class="bg-line"><span class="bg-label">БГ:</span> <span class="bg-value">${fmtRub(fact.bg)}</span></div>
        </td>
      </tr>`;
  });

  body.innerHTML = rows.join('');

  document.getElementById('totCreated').innerHTML  = `${fmtInt(totCreatedCnt)}<br><small>${fmtRub(totCreatedSum)}</small>`;
  document.getElementById('totApproved').innerHTML = `${fmtInt(totApprCnt)}<br><small>${fmtRub(totApprSum)}</small>`;
  document.getElementById('totWon').innerHTML      = `${fmtInt(totWonCnt)}<br><small>${fmtRub(totWonBg)}</small>`;
  document.getElementById('totLose').innerHTML     = `${fmtInt(totLoseCnt)}<br><small>${fmtRub(totLoseSum)}</small>`;
  document.getElementById('totKv').innerHTML =
    `<div class="kv-line"><span class="kv-label">КВ:</span> <span class="kv-value">${fmtRub(totFactKv)}</span></div>
     <div class="bg-line"><span class="bg-label">БГ:</span> <span class="bg-value">${fmtRub(totFactBg)}</span></div>`;

  mpbSwitchZ.classList.toggle('on', mpbMode==='work');
}

document.addEventListener('DOMContentLoaded', () => {
  if (document.getElementById('mpbBody')) {
    renderMPB();
  }
});

if (mpbSwitchZ){
  mpbSwitchZ.style.cursor = 'pointer';
  mpbSwitchZ.setAttribute('role', 'button');
  mpbSwitchZ.setAttribute('tabindex', '0');

  mpbSwitchZ.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    mpbMode = (mpbMode === 'created') ? 'work' : 'created';
    renderMPB();
  });

  mpbSwitchZ.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      mpbSwitchZ.click();
    }
  });
}


// Таб-переключение
const tabBtns = document.querySelectorAll('.tab-pill');
function showTab(key){
  document.querySelectorAll('.tab-panel').forEach(el => el.classList.remove('active'));
  document.querySelector('#tab-'+key)?.classList.add('active');
  tabBtns.forEach(b => b.classList.toggle('active', b.dataset.tab === key));
  history.replaceState(null,'','#'+key);
  if (key === 'mpb') renderMPB();
}
tabBtns.forEach(b => b.addEventListener('click', () => showTab(b.dataset.tab)));
(function initTab(){
  const available = {
    main: !!document.querySelector('#tab-main'),
    mpb:  !!document.querySelector('#tab-mpb')
  };
  let h = (location.hash||'').slice(1);
  if (!available[h]) h = available.main ? 'main' : 'mpb';
  showTab(h);
})();

function openModal(){ document.getElementById('dealModal').style.display='flex'; }
function closeModal(){ document.getElementById('dealModal').style.display='none'; }

document.addEventListener('click', function(e){
  const cell = e.target.closest('.deals-open');
  if (!cell) return;

  const section     = cell.dataset.section || 'mop';
  const managerId   = cell.dataset.managerId;
  const managerName = cell.dataset.managerName || ('ID ' + managerId);
  const type        = cell.dataset.type;   // current|approved|won|lose|winners
  const mode        = cell.dataset.mode;   // today|all|month
  const date        = cell.dataset.date;   // YYYY-MM-DD
  const period      = cell.dataset.period || ''; // <-- ВАЖНО: берём прокинутый период

  let titlePart = '';
  let url = '';

  if (type === 'winners') {
    titlePart = 'Лиды — Победители/обработать';
    url = `winners_modal.php?manager_id=${encodeURIComponent(managerId)}`;
  } else {
    if (type === 'current')      titlePart = (mode === 'today' ? 'Заведено (период)'  : 'В работе');
    else if (type === 'approved')titlePart = (mode === 'today' ? 'Одобрено (период)' : 'Одобрено (все)');
    else if (type === 'won')     titlePart = (mode === 'today' ? 'Выдано (период)'   : 'Выдано за месяц');
    else if (type === 'lose')    titlePart = (mode === 'today' ? 'Не выдано (период)': 'Не выдано за месяц');
    else                         titlePart = 'Сделки';

    url =
      `deals_modal.php?section=${encodeURIComponent(section)}` +
      `&manager_id=${encodeURIComponent(managerId)}` +
      `&type=${encodeURIComponent(type)}` +
      `&mode=${encodeURIComponent(mode)}` +
      `&date=${encodeURIComponent(date)}`;

    if (period) url += `&period=${encodeURIComponent(period)}`; // <-- ПРОКИНУЛИ ПЕРИОД
  }

  document.getElementById('modalTitle').textContent = `${titlePart} — ${managerName}`;
  document.getElementById('modalBody').innerHTML = '<div style="padding:16px; font:14px Inter,system-ui;">Загрузка…</div>';
  openModal();

  fetch(url)
    .then(r => r.text())
    .then(html => { document.getElementById('modalBody').innerHTML = html; })
    .catch(() => { document.getElementById('modalBody').innerHTML = '<div style="padding:16px;color:#b91c1c;">Ошибка загрузки</div>'; });
});

document.getElementById('dealModal').addEventListener('click', (e)=>{
  if (e.target.id === 'dealModal') closeModal();
});
document.addEventListener('keydown', (e)=>{ if (e.key === 'Escape') closeModal(); });
</script>
</body>

</html>
