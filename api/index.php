<?php
declare(strict_types=1);

/* MINAMI Account API - deploy on a separate PHP + MySQL HTTPS host. */
const ALLOWED_ORIGIN = 'https://bagussdwk.github.io';
const SESSION_DAYS = 30;

header('Content-Type: application/json; charset=utf-8');
// API dipakai dari GitHub Pages dan juga saat game dijalankan lokal.
// Tidak memakai cookie/credential browser, jadi wildcard aman untuk endpoint ini.
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Max-Age: 86400');
if ($_SERVER['REQUEST_METHOD']==='OPTIONS') { http_response_code(204); exit; }

if (!is_file(__DIR__.'/config.php')) fail('API belum dikonfigurasi.',500);
$c=require __DIR__.'/config.php';
try {
  // Request statistik/game-result dibuat sering. Jangan jalankan CREATE TABLE/seed
  // pada setiap request karena shared hosting bisa menjadi lambat atau timeout.
  // Struktur tabel diasumsikan sudah dipasang dari schema.sql; endpoint yang
  // memang membutuhkan tabel legacy/setup tetap melakukan ensure secara lokal.
  $db=new PDO(
    'mysql:host='.$c['db_host'].';dbname='.$c['db_name'].';charset=utf8mb4',
    $c['db_user'],$c['db_pass'],
    [
      PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,
      PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC,
      PDO::ATTR_TIMEOUT=>8
    ]
  );
} catch(Throwable $e) {
  error_log('[MINAMI API] DB connect failed: '.$e->getMessage());
  fail('Database tidak dapat dihubungkan.',500);
}

$path=trim(parse_url($_SERVER['REQUEST_URI']??'/',PHP_URL_PATH)??'/','/');
// Some shared hosts do not support PATH_INFO/rewrite for /api/me. Allow ?action=me too.
$queryAction=trim((string)($_GET['action']??''));
if($queryAction!=='') $path=$queryAction;
$prefix=trim($c['api_prefix']??'api','/');
if($prefix && str_starts_with($path,$prefix.'/')) $path=substr($path,strlen($prefix)+1);
$body=json_decode(file_get_contents('php://input')?:'{}',true); if(!is_array($body))$body=[];
switch($path){
  case 'register': if($_SERVER['REQUEST_METHOD']!=='POST')fail('Method tidak valid.',405); registerUser($db,$body); break;
  case 'login': if($_SERVER['REQUEST_METHOD']!=='POST')fail('Method tidak valid.',405); loginUser($db,$body); break;
  case 'logout': if($_SERVER['REQUEST_METHOD']!=='POST')fail('Method tidak valid.',405); logoutUser($db); break;
  case 'me': me($db); break;
  case 'profile-photo': if($_SERVER['REQUEST_METHOD']!=='GET')fail('Method tidak valid.',405); profilePhoto($db); break;
  case 'profile': if($_SERVER['REQUEST_METHOD']!=='POST')fail('Method tidak valid.',405); profile($db,$body); break;
  case 'stats': stats($db); break;
  case 'presence': if($_SERVER['REQUEST_METHOD']!=='POST')fail('Method tidak valid.',405); presence($db,$body); break;
  case 'leaderboard': leaderboard($db); break;
  case 'game-save': if($_SERVER['REQUEST_METHOD']!=='POST')fail('Method tidak valid.',405); gameSave($db,$body); break;
  case 'game-load': if($_SERVER['REQUEST_METHOD']!=='POST')fail('Method tidak valid.',405); gameLoad($db,$body); break;
  case 'game-delete': if($_SERVER['REQUEST_METHOD']!=='POST')fail('Method tidak valid.',405); gameDelete($db,$body); break;
  case 'game-result': if($_SERVER['REQUEST_METHOD']!=='POST')fail('Method tidak valid.',405); gameResult($db,$body); break;
  case 'achievement':
    if($_SERVER['REQUEST_METHOD']==='GET'){ achievementList($db); break; }
    if($_SERVER['REQUEST_METHOD']!=='POST')fail('Method tidak valid.',405);
    // InfinityFree/shared hosting dapat menghapus Authorization header.
    // Sediakan mode POST khusus untuk membaca daftar achievement dengan token
    // di body, tanpa pernah mengubah status achievement.
    if(!empty($body['list'])){ achievementList($db); break; }
    achievement($db,$body); break;
  default: fail('Endpoint tidak ditemukan.',404);
}
function fail(string $m,int $s=400):never{http_response_code($s);echo json_encode(['ok'=>false,'error'=>$m],JSON_UNESCAPED_UNICODE);exit;}
function ok(array $d=[]):never{echo json_encode(['ok'=>true]+$d,JSON_UNESCAPED_UNICODE);exit;}
function auth(PDO $db):array{
  global $body;
  $token='';
  $h=(string)($_SERVER['HTTP_AUTHORIZATION']??'');
  if($h==='')$h=(string)($_SERVER['REDIRECT_HTTP_AUTHORIZATION']??'');
  if($h===''){
    foreach(['Authorization','authorization','HTTP_AUTHORIZATION'] as $k){
      if(isset($_SERVER[$k])&&$_SERVER[$k]!==''){ $h=(string)$_SERVER[$k]; break; }
    }
  }
  if($h===''&&function_exists('getallheaders')){
    $headers=getallheaders();
    foreach($headers as $k=>$v){
      if(strtolower((string)$k)==='authorization'){ $h=(string)$v; break; }
    }
  }
  if(preg_match('/^Bearer\s+(.+)$/i',trim($h),$m))$token=trim($m[1]);
  if($token==='')$token=trim((string)($body['token']??''));
  if($token==='')fail('Login diperlukan.',401);
  $q=$db->prepare('SELECT u.* FROM login_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>NOW() LIMIT 1');
  $q->execute([hash('sha256',$token)]);
  $u=$q->fetch();
  if(!$u)fail('Sesi tidak valid.',401);
  return $u;
}
function registerUser(PDO $db,array $b):never{
  $u=strtolower(trim((string)($b['username']??'')));$p=(string)($b['password']??'');$n=trim((string)($b['display_name']??$u));
  if(!preg_match('/^[a-z0-9_.-]{3,32}$/',$u))fail('Username tidak valid.');
  if(strlen($p)<8)fail('Password minimal 8 karakter.');
  try{
    $db->beginTransaction();
    $q=$db->prepare('INSERT INTO users(username,password_hash,display_name) VALUES(?,?,?)');
    $q->execute([$u,password_hash($p,PASSWORD_DEFAULT),mb_substr($n?:$u,0,40)]);
    $id=(int)$db->lastInsertId();$db->prepare('INSERT INTO player_global_stats(user_id) VALUES(?)')->execute([$id]);$db->commit();
  }catch(Throwable $e){if($db->inTransaction())$db->rollBack();fail('Username sudah dipakai atau pendaftaran gagal.');}
  ok(['message'=>'Akun berhasil dibuat.']);
}
function loginUser(PDO $db,array $b):never{
  $u=strtolower(trim((string)($b['username']??'')));$p=(string)($b['password']??'');
  $q=$db->prepare('SELECT * FROM users WHERE username=? LIMIT 1');$q->execute([$u]);$row=$q->fetch();
  if(!$row||!password_verify($p,$row['password_hash']))fail('Username atau password salah.',401);
  $token=bin2hex(random_bytes(32));$exp=(new DateTimeImmutable('+'.SESSION_DAYS.' days'))->format('Y-m-d H:i:s');
  $db->prepare('INSERT INTO login_sessions(token_hash,user_id,expires_at) VALUES(?,?,?)')->execute([hash('sha256',$token),$row['id'],$exp]);
  ensureUserProfileTable($db);
  $pq=$db->prepare('SELECT profile_id FROM user_profiles WHERE user_id=? LIMIT 1');$pq->execute([$row['id']]);
  $profileId=(string)($pq->fetchColumn()?:'cartoon_01');
  $photoQ=$db->prepare('SELECT profile_photo FROM user_profiles WHERE user_id=? LIMIT 1');$photoQ->execute([$row['id']]);
  $photoUrl=$photoQ->fetchColumn() ? 'api/index.php?action=profile-photo&user_id='.(int)$row['id'] : null;
  ok(['token'=>$token,'user'=>['username'=>$row['username'],'display_name'=>$row['display_name'],'profile_id'=>$profileId,'profile_photo_url'=>$photoUrl]]);
}
function presence(PDO $db,array $b):never{
  $u=auth($db);
  ensurePresenceTable($db);
  $db->prepare('INSERT INTO user_presence(user_id,last_seen) VALUES(?,CURRENT_TIMESTAMP) ON DUPLICATE KEY UPDATE last_seen=CURRENT_TIMESTAMP')->execute([$u['id']]);
  ok(['online'=>true]);
}
function logoutUser(PDO $db):never{
  global $body;
  $token='';
  $h=(string)($_SERVER['HTTP_AUTHORIZATION']??'');
  if(preg_match('/^Bearer\s+(.+)$/i',trim($h),$m))$token=trim($m[1]);
  if($token==='')$token=trim((string)($body['token']??''));
  if($token!==''){
    $hash=hash('sha256',$token);
    $q=$db->prepare('SELECT user_id FROM login_sessions WHERE token_hash=? LIMIT 1');
    $q->execute([$hash]);
    $uid=$q->fetchColumn();
    if($uid)$db->prepare('DELETE FROM user_presence WHERE user_id=?')->execute([(int)$uid]);
    $db->prepare('DELETE FROM login_sessions WHERE token_hash=?')->execute([$hash]);
  }
  ok();
}
function me(PDO $db):never{
  $u=auth($db); ensureUserProfileTable($db);
  $q=$db->prepare('SELECT profile_id,profile_photo FROM user_profiles WHERE user_id=? LIMIT 1');$q->execute([$u['id']]);
  $profileRow=$q->fetch()?:[]; $profile=(string)($profileRow['profile_id']??'cartoon_01');
  $photoUrl=!empty($profileRow['profile_photo']) ? 'api/index.php?action=profile-photo&user_id='.(int)$u['id'] : null;
  ok(['user'=>['username'=>$u['username'],'display_name'=>$u['display_name'],'profile_id'=>$profile,'profile_photo_url'=>$photoUrl]]);
}
function profile(PDO $db,array $b):never{
  $u=auth($db); ensureUserProfileTable($db);
  $id=trim((string)($b['profile_id']??'cartoon_01'));
  if(!preg_match('/^cartoon_(0[1-9]|1[0-2])$/',$id))fail('Profile tidak valid.');
  $uid=(int)$u['id'];
  if(!empty($b['remove_photo'])){
    $q=$db->prepare('INSERT INTO user_profiles(user_id,profile_id,profile_photo,photo_mime) VALUES(?,?,NULL,NULL)
      ON DUPLICATE KEY UPDATE profile_id=VALUES(profile_id),profile_photo=NULL,photo_mime=NULL');
    $q->execute([$uid,$id]); ok(['profile_id'=>$id,'profile_photo_url'=>null,'photo_removed'=>true]);
  }
  if(isset($b['photo_data'])){
    $data=(string)$b['photo_data'];
    if(strlen($data)>700000) fail('Foto terlalu besar setelah diperkecil. Coba foto lain.');
    if(!preg_match('#^data:(image/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$#',$data,$m))fail('Format foto tidak valid.');
    $binary=base64_decode($m[2],true);
    if($binary===false||strlen($binary)<16||strlen($binary)>500000)fail('Ukuran foto maksimal 500 KB.');
    $info=@getimagesizefromstring($binary);
    if(!$info||!in_array($info['mime'],['image/jpeg','image/png','image/webp'],true)||$info['mime']!==$m[1])fail('Isi file bukan gambar yang valid.');
    $q=$db->prepare('INSERT INTO user_profiles(user_id,profile_id,profile_photo,photo_mime) VALUES(?,?,?,?)
      ON DUPLICATE KEY UPDATE profile_id=VALUES(profile_id),profile_photo=VALUES(profile_photo),photo_mime=VALUES(photo_mime)');
    $q->execute([$uid,$id,$binary,$info['mime']]);
    ok(['profile_id'=>$id,'profile_photo_url'=>'api/index.php?action=profile-photo&user_id='.$uid,'photo_saved'=>true]);
  }
  $q=$db->prepare('INSERT INTO user_profiles(user_id,profile_id) VALUES(?,?) ON DUPLICATE KEY UPDATE profile_id=VALUES(profile_id)');
  $q->execute([$uid,$id]); ok(['profile_id'=>$id]);
}
function ensureUserProfileTable(PDO $db):void{
  $db->exec('CREATE TABLE IF NOT EXISTS user_profiles (
    user_id BIGINT UNSIGNED NOT NULL,
    profile_id VARCHAR(32) NOT NULL DEFAULT "cartoon_01",
    profile_photo MEDIUMBLOB NULL,
    photo_mime VARCHAR(32) NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id),
    CONSTRAINT fk_user_profiles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
  $columns=[];
  foreach($db->query("SHOW COLUMNS FROM user_profiles")->fetchAll() as $col) $columns[strtolower((string)$col['Field'])]=true;
  if(!isset($columns['profile_photo'])) $db->exec('ALTER TABLE user_profiles ADD COLUMN profile_photo MEDIUMBLOB NULL AFTER profile_id');
  if(!isset($columns['photo_mime'])) $db->exec('ALTER TABLE user_profiles ADD COLUMN photo_mime VARCHAR(32) NULL AFTER profile_photo');
}
function profilePhoto(PDO $db):never{
  ensureUserProfileTable($db);
  $uid=filter_var($_GET['user_id']??null,FILTER_VALIDATE_INT,['options'=>['min_range'=>1]]);
  if(!$uid){ http_response_code(400); exit; }
  $q=$db->prepare('SELECT profile_photo,photo_mime FROM user_profiles WHERE user_id=? LIMIT 1');
  $q->execute([$uid]); $row=$q->fetch();
  if(!$row||empty($row['profile_photo'])){ http_response_code(404); exit; }
  $mime=(string)($row['photo_mime']??'image/jpeg');
  if(!in_array($mime,['image/jpeg','image/png','image/webp'],true)){ http_response_code(404); exit; }
  header('Content-Type: '.$mime); header('Cache-Control: public, max-age=300'); header('X-Content-Type-Options: nosniff');
  echo $row['profile_photo']; exit;
}
function stats(PDO $db):never{
  $u=auth($db);
  // Repair/synchronize achievement progress from the authoritative stats tables.
  // player_mode_stats/player_global_stats remain the source of truth.
  try{
    ensureAchievementTables($db);
    syncAchievementProgress($db,(int)$u['id']);
  }catch(Throwable $e){
    error_log('[MINAMI API] stats achievement sync failed: '.$e->getMessage());
  }
  $q=$db->prepare('SELECT * FROM player_global_stats WHERE user_id=?');
  $q->execute([$u['id']]);
  $global=$q->fetch()?:[];

  $q2=$db->prepare('SELECT * FROM player_mode_stats WHERE user_id=? ORDER BY FIELD(mode,"minami1","minami2","joker")');
  $q2->execute([$u['id']]);
  $modeStats=[];
  foreach($q2->fetchAll() as $row){
    $mode=(string)$row['mode'];
    $modeStats[$mode]=[
      'games_finished'=>(int)$row['games_finished'],
      'game_wins'=>(int)$row['game_wins'],
      'rank1'=>(int)$row['rank1'],
      'match_finished'=>(int)$row['match_finished'],
      'match_wins'=>(int)$row['match_wins'],
      'tenho'=>(int)$row['tenho'],
      'pots'=>(int)$row['pots'],
      'cards'=>(int)$row['cards'],
      'jokers'=>(int)$row['jokers'],
      'best_combo'=>(int)$row['best_combo'],
      'dead'=>(int)$row['dead'],
      'mvp'=>(int)$row['mvp'],
      'best_streak'=>(int)$row['best_streak'],
      'joker_sets'=>(int)($row['joker_sets']??0),
      'caught'=>(int)($row['caught']??0),
      'caught_by'=>(int)($row['caught_by']??0)
    ];
  }
  ok(['stats'=>$global,'mode_stats'=>$modeStats]);
}
function leaderboard(PDO $db):never{
  // Pastikan tabel profil tersedia agar foto profil pilihan akun ikut dikirim.
  ensureUserProfileTable($db);

  // Leaderboard publik hanya memakai statistik global Rank 1 + Win Game,
  // sedangkan rincian match/statistik lain dikirim per mode.
  $q=$db->query('
    SELECT
      u.id AS user_id,
      u.display_name,
      COALESCE(uf.profile_id,"cartoon_01") AS profile_id,
      CASE WHEN uf.profile_photo IS NOT NULL THEN CONCAT("api/index.php?action=profile-photo&user_id=",u.id) ELSE NULL END AS profile_photo_url,
      CASE WHEN up.last_seen >= (CURRENT_TIMESTAMP - INTERVAL 120 SECOND) THEN 1 ELSE 0 END AS online,
      COALESCE(s.games_finished,0) AS games_finished,
      COALESCE(s.game_wins,0) AS game_wins,
      COALESCE(s.rank1,0) AS rank1
    FROM users u
    LEFT JOIN player_global_stats s ON s.user_id=u.id
    LEFT JOIN user_presence up ON up.user_id=u.id
    LEFT JOIN user_profiles uf ON uf.user_id=u.id
    ORDER BY rank1 DESC, games_finished DESC, game_wins DESC, u.display_name ASC
  ');
  $rows=$q->fetchAll();
  $modeQ=$db->query('
    SELECT user_id,mode,games_finished,game_wins,rank1,match_finished,match_wins,tenho,pots,cards,jokers,best_combo,dead,mvp,best_streak,joker_sets,caught,caught_by
    FROM player_mode_stats
    ORDER BY user_id, FIELD(mode,"minami1","minami2","joker")
  ');
  $byUser=[];
  foreach($modeQ->fetchAll() as $row){
    $uid=(int)$row['user_id'];
    $byUser[$uid][(string)$row['mode']]=[
      'games_finished'=>(int)$row['games_finished'],
      'game_wins'=>(int)$row['game_wins'],
      'rank1'=>(int)$row['rank1'],
      'match_finished'=>(int)$row['match_finished'],
      'match_wins'=>(int)$row['match_wins'],
      'tenho'=>(int)$row['tenho'],
      'pots'=>(int)$row['pots'],
      'cards'=>(int)$row['cards'],
      'jokers'=>(int)$row['jokers'],
      'best_combo'=>(int)$row['best_combo'],
      'dead'=>(int)$row['dead'],
      'mvp'=>(int)$row['mvp'],
      'best_streak'=>(int)$row['best_streak'],
      'joker_sets'=>(int)($row['joker_sets']??0),
      'caught'=>(int)($row['caught']??0),
      'caught_by'=>(int)($row['caught_by']??0)
    ];
  }
  $players=[];
  // Schema lama mungkin belum memiliki kolom user_achievements.level.
  // Jangan biarkan leaderboard menjadi 500 hanya karena migrasi level belum ada.
  $hasLevel=false;
  try{
    $st=$db->query("SHOW COLUMNS FROM user_achievements");
    foreach($st->fetchAll() as $col){
      if(strtolower((string)$col['Field'])==='level'){$hasLevel=true;break;}
    }
  }catch(Throwable $e){}
  $levelSelect=$hasLevel ? 'ua.level' : 'NULL AS level';
  $fq=$db->query("SELECT ufa.user_id,ufa.slot,a.code,a.name,a.description,a.icon,a.mode,$levelSelect
    FROM user_featured_achievements ufa
    JOIN achievements a ON a.id=ufa.achievement_id
    JOIN user_achievements ua ON ua.user_id=ufa.user_id AND ua.achievement_id=ufa.achievement_id
    ORDER BY ufa.user_id,ufa.slot");
  $featuredByUser=[];
  foreach($fq->fetchAll() as $fa){
    $uid=(int)$fa['user_id'];
    $featuredByUser[$uid][]=[
      'slot'=>(int)$fa['slot'],'code'=>$fa['code'],'name'=>$fa['name'],
      'description'=>$fa['description'],'icon'=>$fa['icon'],'mode'=>$fa['mode'],'level'=>(int)($fa['level']??1)
    ];
  }
  foreach($rows as $row){
    $uid=(int)$row['user_id'];
    $players[]=[
      'name'=>mb_substr((string)$row['display_name'],0,40),
      'profile_id'=>(string)($row['profile_id']??'cartoon_01'),
      'profile_photo_url'=>$row['profile_photo_url'] ? (string)$row['profile_photo_url'] : null,
      'online'=>(bool)$row['online'],
      'games_finished'=>(int)$row['games_finished'],
      'game_wins'=>(int)$row['game_wins'],
      'rank1'=>(int)$row['rank1'],
      'mode_stats'=>$byUser[$uid]??[],
      'featured_achievements'=>$featuredByUser[$uid]??[]
    ];
  }
  ok(['players'=>$players]);
}
function ensurePresenceTable(PDO $db):void{
  $db->exec('CREATE TABLE IF NOT EXISTS user_presence (
    user_id BIGINT UNSIGNED NOT NULL,
    last_seen TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id),
    CONSTRAINT fk_user_presence_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
}
function ensureGameSavesTable(PDO $db):void{
  $db->exec('CREATE TABLE IF NOT EXISTS player_game_saves (
    user_id BIGINT UNSIGNED NOT NULL,
    mode VARCHAR(16) NOT NULL,
    state_json MEDIUMTEXT NOT NULL,
    active TINYINT(1) NOT NULL DEFAULT 1,
    revision INT UNSIGNED NOT NULL DEFAULT 1,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, mode),
    CONSTRAINT fk_player_game_saves_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
}
function gameSave(PDO $db,array $b):never{
  $u=auth($db);
  ensureGameSavesTable($db);
  $mode=trim((string)($b['mode']??''));
  if(!in_array($mode,['minami1','minami2','joker'],true))fail('Mode tidak valid.');
  $state=$b['state']??null;
  if(!is_array($state))fail('Data permainan tidak valid.');
  $json=json_encode($state,JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
  if($json===false)fail('Data permainan tidak dapat disimpan.');
  if(strlen($json)>12000000)fail('Data permainan terlalu besar.');
  $active=($b['active']??true)?1:0;
  $sql='INSERT INTO player_game_saves(user_id,mode,state_json,active,revision)
        VALUES(?,?,?,?,1)
        ON DUPLICATE KEY UPDATE
          state_json=VALUES(state_json),
          active=VALUES(active),
          revision=revision+1,
          updated_at=CURRENT_TIMESTAMP';
  $db->prepare($sql)->execute([$u['id'],$mode,$json,$active]);
  $q=$db->prepare('SELECT mode,active,revision,updated_at,state_json FROM player_game_saves WHERE user_id=? AND mode=? LIMIT 1');
  $q->execute([$u['id'],$mode]);
  $row=$q->fetch();
  if(!$row)fail('Data permainan gagal disimpan.',500);
  ok(['save'=>[
    'mode'=>$row['mode'],
    'active'=>(bool)$row['active'],
    'revision'=>(int)$row['revision'],
    'updated_at'=>$row['updated_at']
  ]]);
}
function gameLoad(PDO $db,array $b):never{
  $u=auth($db);
  ensureGameSavesTable($db);
  $mode=trim((string)($b['mode']??''));
  if($mode!=='') {
    if(!in_array($mode,['minami1','minami2','joker'],true))fail('Mode tidak valid.');
    $q=$db->prepare('SELECT mode,active,revision,updated_at,state_json FROM player_game_saves WHERE user_id=? AND mode=? AND active=1 LIMIT 1');
    $q->execute([$u['id'],$mode]);
  } else {
    $q=$db->prepare('SELECT mode,active,revision,updated_at,state_json FROM player_game_saves WHERE user_id=? AND active=1 ORDER BY updated_at DESC');
    $q->execute([$u['id']]);
  }
  $rows=$q->fetchAll();
  $saves=[];
  foreach($rows as $row){
    $state=json_decode((string)$row['state_json'],true);
    if(!is_array($state))continue;
    $saves[]=[
      'mode'=>$row['mode'],
      'active'=>(bool)$row['active'],
      'revision'=>(int)$row['revision'],
      'updated_at'=>$row['updated_at'],
      'state'=>$state
    ];
  }
  ok(['saves'=>$saves,'save'=>$saves[0]??null]);
}
function gameDelete(PDO $db,array $b):never{
  $u=auth($db);
  ensureGameSavesTable($db);
  $mode=trim((string)($b['mode']??''));
  if($mode!==''){
    if(!in_array($mode,['minami1','minami2','joker'],true))fail('Mode tidak valid.');
    $q=$db->prepare('DELETE FROM player_game_saves WHERE user_id=? AND mode=?');
    $q->execute([$u['id'],$mode]);
  } else {
    $db->prepare('DELETE FROM player_game_saves WHERE user_id=?')->execute([$u['id']]);
  }
  ok();
}
function gameResult(PDO $db,array $b):never{
  $u=auth($db);
  $mode=trim((string)($b['mode']??''));
  if(!in_array($mode,['minami1','minami2','joker'],true))fail('Mode tidak valid.');

  $eventId=trim((string)($b['event_id']??''));
  if($eventId===''||strlen($eventId)>128)fail('Event statistik tidak valid.');

  $keys=[
    'games_finished','game_wins','rank1','match_finished','match_wins',
    'tenho','pots','cards','jokers','dead','mvp','joker_sets','caught','caught_by'
  ];
  $vals=[];
  foreach($keys as $k){
    $v=(int)($b[$k]??0);
    if($v<0||$v>1000000)fail('Statistik tidak valid.');
    $vals[$k]=$v;
  }
  $vals['best_combo']=max(0,min(100,(int)($b['best_combo']??0)));
  $vals['best_streak']=max(0,min(1000000,(int)($b['best_streak']??0)));

  $db->beginTransaction();
  try{
    $q=$db->prepare('INSERT IGNORE INTO player_stat_events(user_id,event_id) VALUES(?,?)');
    $q->execute([$u['id'],$eventId]);
    if($q->rowCount()===0){
      $db->commit();
      // A duplicate event must not prevent a repair of stale achievement progress.
      try{
        ensureAchievementTables($db);
        syncAchievementProgress($db,(int)$u['id']);
      }catch(Throwable $e){
        error_log('[MINAMI API] duplicate game-result achievement sync failed: '.$e->getMessage());
        fail('Progress achievement gagal disinkronkan.',500);
      }
      ok(['duplicate'=>true]);
    }

    $cols='games_finished,game_wins,rank1,match_finished,match_wins,tenho,pots,cards,jokers,best_combo,dead,mvp,best_streak,joker_sets,caught,caught_by';
    $params=[$u['id'],$mode,$vals['games_finished'],$vals['game_wins'],$vals['rank1'],$vals['match_finished'],$vals['match_wins'],$vals['tenho'],$vals['pots'],$vals['cards'],$vals['jokers'],$vals['best_combo'],$vals['dead'],$vals['mvp'],$vals['best_streak'],$vals['joker_sets'],$vals['caught'],$vals['caught_by']];
    $sql='INSERT INTO player_mode_stats(user_id,mode,'.$cols.') VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      ON DUPLICATE KEY UPDATE
      games_finished=games_finished+VALUES(games_finished),
      game_wins=game_wins+VALUES(game_wins),
      rank1=rank1+VALUES(rank1),
      match_finished=match_finished+VALUES(match_finished),
      match_wins=match_wins+VALUES(match_wins),
      tenho=tenho+VALUES(tenho),
      pots=pots+VALUES(pots),
      cards=cards+VALUES(cards),
      jokers=jokers+VALUES(jokers),
      best_combo=GREATEST(best_combo,VALUES(best_combo)),
      dead=dead+VALUES(dead),
      mvp=mvp+VALUES(mvp),
      best_streak=GREATEST(best_streak,VALUES(best_streak)),
      joker_sets=joker_sets+VALUES(joker_sets),
      caught=caught+VALUES(caught),
      caught_by=caught_by+VALUES(caught_by)';
    $db->prepare($sql)->execute($params);

    $sql2='UPDATE player_global_stats SET
      games_finished=games_finished+?, game_wins=game_wins+?, rank1=rank1+?,
      match_finished=match_finished+?, match_wins=match_wins+?,
      tenho=tenho+?, pots=pots+?, cards=cards+?, jokers=jokers+?,
      best_combo=GREATEST(best_combo,?), dead=dead+?, mvp=mvp+?,
      best_streak=GREATEST(best_streak,?)
      WHERE user_id=?';
    $db->prepare($sql2)->execute([
      $vals['games_finished'],$vals['game_wins'],$vals['rank1'],
      $vals['match_finished'],$vals['match_wins'],
      $vals['tenho'],$vals['pots'],$vals['cards'],$vals['jokers'],
      $vals['best_combo'],$vals['dead'],$vals['mvp'],$vals['best_streak'],$u['id']
    ]);
    $db->commit();

    // Statistics are committed first. Then rebuild achievement progress from
    // the newly committed player_mode_stats/player_global_stats values.
    // This keeps player_achievement_stats synchronized with the real statistics.
    try{
      ensureAchievementTables($db);
      syncAchievementProgress($db,(int)$u['id']);
    }catch(Throwable $e){
      error_log('[MINAMI API] game-result achievement sync failed: '.$e->getMessage());
      fail('Statistik tersimpan, tetapi progress achievement gagal disinkronkan.',500);
    }
    ok();
  }catch(Throwable $e){
    if($db->inTransaction())$db->rollBack();
    // Jangan tampilkan detail SQL ke client, tetapi simpan di error log hosting
    // agar kegagalan game-result bisa ditelusuri tanpa membocorkan struktur DB.
    error_log('[MINAMI API] game-result failed: '.$e->getMessage());
    fail('Statistik gagal disimpan.',500);
  }
}
function ensureAchievementTables(PDO $db):void{
  /*
   * Sinkronisasi master achievement yang aman untuk schema lama maupun schema baru.
   * Schema InfinityFree saat ini memakai achievements.id VARCHAR(64) sebagai PK.
   * Jangan pernah menghapus/mengganti id lama karena user_achievements bergantung pada PK tersebut.
   */
  $cols=[];
  try{
    $st=$db->query("SHOW COLUMNS FROM achievements");
    foreach($st->fetchAll() as $row){
      $cols[strtolower((string)$row['Field'])]=strtolower((string)$row['Type']);
    }
  }catch(Throwable $e){$cols=[];}

  if(!$cols){
    $db->exec('CREATE TABLE IF NOT EXISTS achievements (
      id VARCHAR(64) NOT NULL,
      mode VARCHAR(16) NOT NULL,
      name VARCHAR(120) NOT NULL,
      description VARCHAR(255) NOT NULL,
      code VARCHAR(64) NOT NULL,
      icon VARCHAR(16) NOT NULL DEFAULT "🏆",
      sort_order INT NOT NULL DEFAULT 0,
      PRIMARY KEY(id),
      UNIQUE KEY uq_achievement_code(code)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
    $st=$db->query("SHOW COLUMNS FROM achievements");
    foreach($st->fetchAll() as $row){
      $cols[strtolower((string)$row['Field'])]=strtolower((string)$row['Type']);
    }
  }

  /* Pastikan kolom master yang diperlukan tersedia. */
  if(!isset($cols['code'])){
    $db->exec("ALTER TABLE achievements ADD COLUMN code VARCHAR(64) NULL");
    $db->exec("UPDATE achievements SET code=CAST(id AS CHAR) WHERE code IS NULL OR code=''");
    $db->exec("ALTER TABLE achievements MODIFY code VARCHAR(64) NOT NULL");
    try{$db->exec("ALTER TABLE achievements ADD UNIQUE KEY uq_achievement_code(code)");}catch(Throwable $e){}
  }
  if(!isset($cols['icon'])){
    $db->exec("ALTER TABLE achievements ADD COLUMN icon VARCHAR(16) NOT NULL DEFAULT '🏆'");
  }
  if(!isset($cols['sort_order'])){
    $db->exec("ALTER TABLE achievements ADD COLUMN sort_order INT NOT NULL DEFAULT 0");
  }

  /* Emoji achievement wajib disimpan dengan utf8mb4. */
  try{$db->exec("ALTER TABLE achievements CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");}catch(Throwable $e){}

  /* Tipe FK harus mengikuti tipe achievements.id yang benar-benar ada. */
  $idType=(string)($cols['id']??'varchar(64)');
  $achIdType=(stripos($idType,'bigint')!==false||stripos($idType,'int')!==false)?'BIGINT UNSIGNED':'VARCHAR(64)';

  $db->exec("CREATE TABLE IF NOT EXISTS user_achievements (
    user_id BIGINT UNSIGNED NOT NULL,
    achievement_id $achIdType NOT NULL,
    level TINYINT UNSIGNED NOT NULL DEFAULT 1,
    unlocked_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(user_id,achievement_id),
    CONSTRAINT fk_user_ach_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_ach_achievement FOREIGN KEY(achievement_id) REFERENCES achievements(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

  // Level achievement ditambahkan secara backward-compatible.
  // Data unlock lama tetap ada dan otomatis dianggap level I.
  try{
    $st=$db->query("SHOW COLUMNS FROM user_achievements");
    $hasLevel=false;
    foreach($st->fetchAll() as $row){
      if(strtolower((string)$row['Field'])==='level'){$hasLevel=true;break;}
    }
    if(!$hasLevel) $db->exec("ALTER TABLE user_achievements ADD COLUMN level TINYINT UNSIGNED NOT NULL DEFAULT 1 AFTER achievement_id");
  }catch(Throwable $e){
    error_log('[MINAMI API] achievement level migration: '.$e->getMessage());
  }

  $db->exec("CREATE TABLE IF NOT EXISTS user_featured_achievements (
    user_id BIGINT UNSIGNED NOT NULL,
    achievement_id $achIdType NOT NULL,
    slot TINYINT UNSIGNED NOT NULL,
    PRIMARY KEY(user_id,slot),
    UNIQUE KEY uq_user_featured_achievement(user_id,achievement_id),
    CONSTRAINT fk_user_featured_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_featured_achievement FOREIGN KEY(achievement_id) REFERENCES achievements(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

  $items=[
    ['first-win','First Win','Menang 1 match','🏆','global',10],
    ['first-champion','First Champion','Menang 1 Game sampai target poin','👑','global',20],
    ['tenho','TENHO!','Mendapatkan TENHO di Minami','🃏','minami',30],
    ['pot-master','POT Hunter','Membuat 5 POT','♟️','minami',40],
    ['joker-master','Joker Master','Memainkan Joker 5 kali','🃏','minami',50],
    ['combo-master','Combo Master','Menurunkan 5 kartu atau lebih sekaligus','🔥','minami',60],
    ['mvp','MVP','Menjadi MVP 1 kali','⭐','minami',70],
    ['rank-climber','Rank Climber','Mengumpulkan 10 Rank 1','📈','minami',80],
    ['marathon','Marathon','Menyelesaikan 10 Game sampai target','🎴','minami',90],
    ['triple-champion','Triple Champion','Menang 3 Game sampai target','🏆','minami',100],
    ['veteran','Veteran','Menyelesaikan 25 match','🎖️','minami',110],
    ['streak-3','Winning Streak','Menang 3 match berturut-turut','⚡','minami',120],
    ['minami2-clean-5','Clean Five','Menyelesaikan 5 Game Minami 2 berturut-turut tanpa mati tangan','🛡️','minami2',125],
    ['first-joker','First Joker','Menggunakan Joker pertama dalam kombinasi','🃏','joker',130],
    ['set-master','Set Master','Membuat set pertama','🎯','joker',140],
    ['joker-collector','Joker Collector','Menggunakan 10 Joker','🔥','joker',150],
    ['joker-hoarder','Joker Hoarder','Menggunakan 25 Joker','💎','joker',160],
    ['triple-set','Triple Set','Membuat 3 set dalam satu match','🎴','joker',170],
    ['perfect-close','Perfect Close','Menutup dengan Joker','⚡','joker',180],
    ['gotcha','Gotcha!','Mengambil buangan lalu langsung menutup','🪤','joker',190],
    ['payback','Payback','Buanganmu diambil lawan lalu lawan menutup','😈','joker',200],
    ['hot-streak','Hot Streak','Rank 1 dalam 3 match berturut-turut','🔥','joker',210],
    ['unstoppable','Unstoppable','Rank 1 dalam 5 match berturut-turut','👑','joker',220],
    ['dead-hand','Dead Hand','Mati tangan karena tidak memiliki Dasar legal pada putaran pertama','💀','minami',230]
  ];

  /*
   * Seed berdasarkan code tanpa INSERT IGNORE.
   * Jika achievement sudah ada, metadata diperbarui tanpa mengganti id/PK.
   * Jika belum ada, id=code dibuat. Dengan cara ini seluruh 24 item tetap masuk
   * walaupun sebelumnya baru ada First Win.
   */
  $find=$db->prepare('SELECT id FROM achievements WHERE code=? LIMIT 1');
  $ins=$db->prepare('INSERT INTO achievements(id,code,name,description,icon,mode,sort_order) VALUES(?,?,?,?,?,?,?)');
  $upd=$db->prepare('UPDATE achievements SET name=?,description=?,icon=?,mode=?,sort_order=? WHERE code=?');
  foreach($items as $x){
    $find->execute([$x[0]]);
    $row=$find->fetch();
    if($row){
      $upd->execute([$x[1],$x[2],$x[3],$x[4],$x[5],$x[0]]);
    }else{
      $ins->execute([$x[0],$x[0],$x[1],$x[2],$x[3],$x[4],$x[5]]);
    }
  }
}

function ensureAchievementProgressTable(PDO $db):void{
  $db->exec('CREATE TABLE IF NOT EXISTS player_achievement_stats (
    user_id BIGINT UNSIGNED NOT NULL,
    achievement_id VARCHAR(64) NOT NULL,
    mode VARCHAR(16) NOT NULL,
    progress INT UNSIGNED NOT NULL DEFAULT 0,
    level TINYINT UNSIGNED NOT NULL DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY(user_id,achievement_id),
    INDEX idx_player_achievement_mode(user_id,mode),
    CONSTRAINT fk_player_achievement_stats_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_player_achievement_stats_achievement FOREIGN KEY(achievement_id) REFERENCES achievements(id) ON DELETE CASCADE
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4');
}

function syncAchievementProgress(PDO $db,int $userId):void{
  ensureAchievementProgressTable($db);

  $q=$db->query('SELECT id,code,mode FROM achievements ORDER BY sort_order,id');
  $rows=$q->fetchAll();
  if(!$rows)return;

  $up=$db->prepare('INSERT INTO player_achievement_stats
    (user_id,achievement_id,mode,progress,level)
    VALUES(?,?,?,?,?)
    ON DUPLICATE KEY UPDATE
      mode=VALUES(mode),
      progress=VALUES(progress),
      level=VALUES(level)');

  foreach($rows as $a){
    $code=(string)$a['code'];
    $progress=achievementProgressValue($db,$userId,$code);
    $level=achievementRequiredLevel($code,$progress);
    $up->execute([
      $userId,
      (string)$a['id'],
      (string)$a['mode'],
      $progress,
      $level
    ]);
  }
}

function achievementProgressValue(PDO $db,int $userId,string $code):int{
  static $cache=[];
  if(isset($cache[$userId][$code]))return $cache[$userId][$code];

  if(!isset($cache[$userId])){
    $cache[$userId]=[];

    $g=$db->prepare('SELECT * FROM player_global_stats WHERE user_id=? LIMIT 1');
    $g->execute([$userId]);
    $cache[$userId]['__global']=$g->fetch()?:[];

    $m=$db->prepare('SELECT * FROM player_mode_stats WHERE user_id=?');
    $m->execute([$userId]);
    foreach($m->fetchAll() as $row){
      $cache[$userId]['__mode_'.(string)$row['mode']]=$row;
    }
  }

  $g=$cache[$userId]['__global']??[];
  $m1=$cache[$userId]['__mode_minami1']??[];
  $m2=$cache[$userId]['__mode_minami2']??[];
  $j=$cache[$userId]['__mode_joker']??[];

  $v=match($code){
    'first-win'       => (int)($g['match_wins']??0),
    'first-champion'  => (int)($g['game_wins']??0),
    'tenho'           => (int)($g['tenho']??0),
    'pot-master'      => (int)($g['pots']??0),
    'joker-master'    => (int)($g['jokers']??0),
    'combo-master'    => (int)($g['best_combo']??0),
    'mvp'             => (int)($g['mvp']??0),
    'rank-climber'    => (int)($g['rank1']??0),
    'marathon'        => (int)($g['games_finished']??0),
    'triple-champion' => (int)($g['game_wins']??0),
    'veteran'         => (int)($g['match_finished']??0),
    'streak-3'        => (int)($g['best_streak']??0),
    'first-joker'     => (int)($j['jokers']??0),
    'set-master'      => (int)($j['joker_sets']??0),
    'joker-collector' => (int)($j['jokers']??0),
    'joker-hoarder'   => (int)($j['jokers']??0),
    'triple-set'      => (int)($j['triple_sets']??0),
    'perfect-close'   => (int)($j['perfect_closes']??0),
    'gotcha'          => (int)($j['caught']??0),
    'payback'         => (int)($j['caught_by']??0),
    'hot-streak'      => (int)($j['best_streak']??0),
    'unstoppable'     => (int)($j['best_streak']??0),
    'dead-hand'       => max((int)($m1['dead']??0),(int)($m2['dead']??0)),
    default           => 0
  };

  $cache[$userId][$code]=max(0,$v);
  return $cache[$userId][$code];
}

function achievementRequiredLevel(string $code,int $value):int{
  $tiers=[
    'first-win'=>[1,5,10],
    'first-champion'=>[1,5,10],
    'tenho'=>[1,5,15],
    'pot-master'=>[5,15,30],
    'joker-master'=>[5,25,50],
    'combo-master'=>[5,7,10],
    'mvp'=>[1,5,15],
    'rank-climber'=>[10,25,50],
    'marathon'=>[10,25,50],
    'triple-champion'=>[3,10,25],
    'veteran'=>[25,50,100],
    'streak-3'=>[3,5,10],
    'first-joker'=>[1,5,10],
    'set-master'=>[1,5,10],
    'joker-collector'=>[10,25,50],
    'joker-hoarder'=>[25,50,100],
    'triple-set'=>[1,5,10],
    'perfect-close'=>[1,5,10],
    'gotcha'=>[1,5,10],
    'payback'=>[1,5,10],
    'hot-streak'=>[3,5,10],
    'unstoppable'=>[5,10,20],
    'dead-hand'=>[1,5,10]
  ];
  if(!isset($tiers[$code]))return 0;
  $t=$tiers[$code];
  if($value>=$t[2])return 3;
  if($value>=$t[1])return 2;
  if($value>=$t[0])return 1;
  return 0;
}

function achievementList(PDO $db):never{
  // Endpoint baca harus ringan agar tidak timeout di shared hosting.
  // Jangan mengasumsikan kolom level sudah ada: schema lama masih mungkin
  // belum bermigrasi. Jika level belum ada, achievement lama tetap dibaca
  // sebagai Level I tanpa memicu error SQL/502.
  $u=auth($db);
  $hasLevel=false;
  try{
    $st=$db->query("SHOW COLUMNS FROM user_achievements");
    foreach($st->fetchAll() as $row){
      if(strtolower((string)$row['Field'])==='level'){$hasLevel=true;break;}
    }
  }catch(Throwable $e){}
  $levelSelect=$hasLevel ? 'ua.level' : 'NULL AS level';
  $q=$db->prepare("SELECT a.code,a.name,a.description,a.icon,a.mode,$levelSelect,ua.unlocked_at
    FROM achievements a
    LEFT JOIN user_achievements ua ON ua.achievement_id=a.id AND ua.user_id=?
    ORDER BY a.sort_order,a.id");
  $q->execute([$u['id']]);
  $rows=$q->fetchAll();
  $out=[]; foreach($rows as $r){$out[]=['code'=>$r['code'],'name'=>$r['name'],'description'=>$r['description'],'icon'=>$r['icon'],'mode'=>$r['mode'],'level'=>(int)($r['level']??0),'unlocked'=>(bool)$r['unlocked_at'],'unlocked_at'=>$r['unlocked_at']];}
  // Featured sudah divalidasi saat disimpan hanya dari achievement yang unlocked.
  // Saat membaca ulang, cukup ambil dari tabel featured + master achievement.
  // Jangan JOIN ulang ke user_achievements karena perubahan/legacy ID dapat
  // membuat pilihan yang sebenarnya tersimpan terlihat hilang setelah refresh.
  $f=$db->prepare('SELECT a.code FROM user_featured_achievements f JOIN achievements a ON a.id=f.achievement_id WHERE f.user_id=? ORDER BY f.slot');
  $f->execute([$u['id']]);
  $featured=array_map(fn($x)=>(string)$x['code'],$f->fetchAll());
  ok(['achievements'=>$out,'featured_achievements'=>$featured]);
}
function achievement(PDO $db,array $b):never{
  // Endpoint tulis memakai tabel achievement yang sudah dipasang saat setup.

  $u=auth($db);
  if(array_key_exists('featured_codes',$b)){
    $codes=$b['featured_codes'];
    if(!is_array($codes))fail('Achievement pilihan tidak valid.');
    $codes=array_values(array_unique(array_map(fn($x)=>trim((string)$x),$codes)));
    if(count($codes)>3)fail('Maksimal 3 achievement.');
    $find=$db->prepare('SELECT a.id FROM achievements a JOIN user_achievements ua ON ua.achievement_id=a.id AND ua.user_id=? WHERE a.code=? LIMIT 1');
    $ids=[];
    foreach($codes as $code){
      if(!preg_match('/^[a-z0-9_-]{1,64}$/',$code))continue;
      $find->execute([$u['id'],$code]);
      $row=$find->fetch();
      if($row)$ids[]=(string)$row['id'];
    }
    $db->beginTransaction();
    try{
      $db->prepare('DELETE FROM user_featured_achievements WHERE user_id=?')->execute([$u['id']]);
      $ins=$db->prepare('INSERT INTO user_featured_achievements(user_id,achievement_id,slot) VALUES(?,?,?)');
      foreach($ids as $i=>$id)$ins->execute([$u['id'],$id,$i+1]);
      $db->commit();
    }catch(Throwable $e){if($db->inTransaction())$db->rollBack();fail('Achievement pilihan gagal disimpan.',500);}
    $savedCodes=[];
    if($ids){
      $sq=$db->prepare('SELECT code FROM achievements WHERE id=? LIMIT 1');
      foreach($ids as $id){$sq->execute([$id]);$rr=$sq->fetch();if($rr)$savedCodes[]=(string)$rr['code'];}
    }
    ok(['saved'=>count($savedCodes),'featured_codes'=>$savedCodes]);
  }
  $ids=$b['achievement_ids']??[$b['achievement_id']??''];
  if(!is_array($ids))$ids=[$ids];

  $levels=is_array($b['achievement_levels']??null)?$b['achievement_levels']:[];
  $q=$db->prepare('SELECT id FROM achievements WHERE code=? LIMIT 1');

  // Dukungan schema lama: bila kolom level belum ada, tetap simpan unlock
  // menggunakan format lama. Ini mencegah 500/502 hanya karena migrasi level
  // belum sempat dijalankan di shared hosting.
  $hasLevel=false;
  try{
    $st=$db->query("SHOW COLUMNS FROM user_achievements");
    foreach($st->fetchAll() as $row){
      if(strtolower((string)$row['Field'])==='level'){$hasLevel=true;break;}
    }
    // Migrasi hanya sekali, tepat saat user menyimpan achievement level.
    // Setelah kolom ada, request berikutnya tidak menjalankan ALTER TABLE lagi.
    if(!$hasLevel){
      $db->exec("ALTER TABLE user_achievements ADD COLUMN level TINYINT UNSIGNED NOT NULL DEFAULT 1 AFTER achievement_id");
      $hasLevel=true;
    }
  }catch(Throwable $e){
    error_log('[MINAMI API] achievement level migration: '.$e->getMessage());
  }
  $ins=$hasLevel
    ? $db->prepare('INSERT INTO user_achievements(user_id,achievement_id,level) VALUES(?,?,?)
      ON DUPLICATE KEY UPDATE level=GREATEST(level,VALUES(level))')
    : $db->prepare('INSERT INTO user_achievements(user_id,achievement_id) VALUES(?,?)
      ON DUPLICATE KEY UPDATE achievement_id=VALUES(achievement_id)');
  $count=0;
  foreach($ids as $id){
    $id=trim((string)$id);
    if(!preg_match('/^[a-z0-9_-]{1,64}$/',$id))continue;
    $q->execute([$id]);$a=$q->fetch();
    if($a){
      if($hasLevel){
        $level=(int)($levels[$id]??1);
        if($level<1)$level=1;
        if($level>3)$level=3;
        $ins->execute([$u['id'],$a['id'],$level]);
      }else{
        $ins->execute([$u['id'],$a['id']]);
      }
      $count++;
    }
  }
  ok(['saved'=>$count]);
}