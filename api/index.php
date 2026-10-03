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
  $db=new PDO(
    'mysql:host='.$c['db_host'].';dbname='.$c['db_name'].';charset=utf8mb4',
    $c['db_user'],$c['db_pass'],
    [PDO::ATTR_ERRMODE=>PDO::ERRMODE_EXCEPTION,PDO::ATTR_DEFAULT_FETCH_MODE=>PDO::FETCH_ASSOC]
  );
} catch(Throwable $e) { fail('Database tidak dapat dihubungkan.',500); }

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
  case 'stats': stats($db); break;
  case 'leaderboard': leaderboard($db); break;
  case 'game-save': if($_SERVER['REQUEST_METHOD']!=='POST')fail('Method tidak valid.',405); gameSave($db,$body); break;
  case 'game-load': if($_SERVER['REQUEST_METHOD']!=='POST')fail('Method tidak valid.',405); gameLoad($db,$body); break;
  case 'game-delete': if($_SERVER['REQUEST_METHOD']!=='POST')fail('Method tidak valid.',405); gameDelete($db,$body); break;
  case 'game-result': if($_SERVER['REQUEST_METHOD']!=='POST')fail('Method tidak valid.',405); gameResult($db,$body); break;
  case 'achievement': if($_SERVER['REQUEST_METHOD']!=='POST')fail('Method tidak valid.',405); achievement($db,$body); break;
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
  ok(['token'=>$token,'user'=>['username'=>$row['username'],'display_name'=>$row['display_name']]]);
}
function logoutUser(PDO $db):never{
  global $body;
  $token='';
  $h=(string)($_SERVER['HTTP_AUTHORIZATION']??'');
  if(preg_match('/^Bearer\s+(.+)$/i',trim($h),$m))$token=trim($m[1]);
  if($token==='')$token=trim((string)($body['token']??''));
  if($token!=='')$db->prepare('DELETE FROM login_sessions WHERE token_hash=?')->execute([hash('sha256',$token)]);
  ok();
}
function me(PDO $db):never{$u=auth($db);ok(['user'=>['username'=>$u['username'],'display_name'=>$u['display_name']]]);}
function stats(PDO $db):never{
  $u=auth($db);
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
      'best_streak'=>(int)$row['best_streak']
    ];
  }
  ok(['stats'=>$global,'mode_stats'=>$modeStats]);
}
function leaderboard(PDO $db):never{
  // Leaderboard publik hanya memakai statistik global Rank 1 + Win Game,
  // sedangkan rincian match/statistik lain dikirim per mode.
  $q=$db->query('
    SELECT
      u.id AS user_id,
      u.display_name,
      COALESCE(s.games_finished,0) AS games_finished,
      COALESCE(s.game_wins,0) AS game_wins,
      COALESCE(s.rank1,0) AS rank1
    FROM users u
    LEFT JOIN player_global_stats s ON s.user_id=u.id
    ORDER BY rank1 DESC, games_finished DESC, game_wins DESC, u.display_name ASC
  ');
  $rows=$q->fetchAll();
  $modeQ=$db->query('
    SELECT user_id,mode,games_finished,game_wins,rank1,match_finished,match_wins,tenho,pots,cards,jokers,best_combo,dead,mvp,best_streak
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
      'best_streak'=>(int)$row['best_streak']
    ];
  }
  $players=[];
  foreach($rows as $row){
    $uid=(int)$row['user_id'];
    $players[]=[
      'name'=>mb_substr((string)$row['display_name'],0,40),
      'games_finished'=>(int)$row['games_finished'],
      'game_wins'=>(int)$row['game_wins'],
      'rank1'=>(int)$row['rank1'],
      'mode_stats'=>$byUser[$uid]??[]
    ];
  }
  ok(['players'=>$players]);
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
    'tenho','pots','cards','jokers','dead','mvp'
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
      ok(['duplicate'=>true]);
    }

    $cols='games_finished,game_wins,rank1,match_finished,match_wins,tenho,pots,cards,jokers,best_combo,dead,mvp,best_streak';
    $params=[$u['id'],$mode,$vals['games_finished'],$vals['game_wins'],$vals['rank1'],$vals['match_finished'],$vals['match_wins'],$vals['tenho'],$vals['pots'],$vals['cards'],$vals['jokers'],$vals['best_combo'],$vals['dead'],$vals['mvp'],$vals['best_streak']];
    $sql='INSERT INTO player_mode_stats(user_id,mode,'.$cols.') VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
      best_streak=GREATEST(best_streak,VALUES(best_streak))';
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
    ok();
  }catch(Throwable $e){
    if($db->inTransaction())$db->rollBack();
    fail('Statistik gagal disimpan.',500);
  }
}
function achievement(PDO $db,array $b):never{
  $u=auth($db);$id=trim((string)($b['achievement_id']??''));if(!preg_match('/^[a-z0-9_-]{1,64}$/',$id))fail('Achievement tidak valid.');
  $db->prepare('INSERT IGNORE INTO user_achievements(user_id,achievement_id) VALUES(?,?)')->execute([$u['id'],$id]);ok();
}