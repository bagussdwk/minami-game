<?php
declare(strict_types=1);

/* MINAMI Account API - deploy on a separate PHP + MySQL HTTPS host. */
const ALLOWED_ORIGIN = 'https://bagussdwk.github.io';
const SESSION_DAYS = 30;

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: '.ALLOWED_ORIGIN);
header('Vary: Origin');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
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
function stats(PDO $db):never{$u=auth($db);$q=$db->prepare('SELECT * FROM player_global_stats WHERE user_id=?');$q->execute([$u['id']]);ok(['stats'=>$q->fetch()?:[]]);}
function gameResult(PDO $db,array $b):never{
  $u=auth($db);$mode=trim((string)($b['mode']??''));if(!in_array($mode,['minami1','minami2','joker'],true))fail('Mode tidak valid.');
  $vals=[];foreach(['games_finished','game_wins','rank1','match_finished','match_wins'] as $k){$v=(int)($b[$k]??0);if($v<0||$v>100000)fail('Statistik tidak valid.');$vals[$k]=$v;}
  $db->beginTransaction();
  $sql='INSERT INTO player_mode_stats(user_id,mode,games_finished,game_wins,rank1,match_finished,match_wins) VALUES(?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE games_finished=games_finished+VALUES(games_finished),game_wins=game_wins+VALUES(game_wins),rank1=rank1+VALUES(rank1),match_finished=match_finished+VALUES(match_finished),match_wins=match_wins+VALUES(match_wins)';
  $db->prepare($sql)->execute([$u['id'],$mode,$vals['games_finished'],$vals['game_wins'],$vals['rank1'],$vals['match_finished'],$vals['match_wins']]);
  $db->prepare('UPDATE player_global_stats SET games_finished=games_finished+?,game_wins=game_wins+?,rank1=rank1+?,match_finished=match_finished+?,match_wins=match_wins+? WHERE user_id=?')->execute([$vals['games_finished'],$vals['game_wins'],$vals['rank1'],$vals['match_finished'],$vals['match_wins'],$u['id']]);
  $db->commit();ok();
}
function achievement(PDO $db,array $b):never{
  $u=auth($db);$id=trim((string)($b['achievement_id']??''));if(!preg_match('/^[a-z0-9_-]{1,64}$/',$id))fail('Achievement tidak valid.');
  $db->prepare('INSERT IGNORE INTO user_achievements(user_id,achievement_id) VALUES(?,?)')->execute([$u['id'],$id]);ok();
}