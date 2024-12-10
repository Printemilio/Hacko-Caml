(*Paul Ourliac , Emilio Decaix-Massiani*)


(*Donne les couple login/mots de passe contenue dans un fichier*)
let read_data_from_file file =

  let f = open_in file in
  let rec aux acc =
    try
      let login = input_line f 
      and pwd = input_line f
      in
      aux ((login, pwd) :: acc)
    with End_of_file ->
      close_in f;
      List.rev acc
  in
  aux []
;;

  
#use "topfind";;
#require "cryptokit";;
#require "base64";;
  
(*hache un mot de passe*)  
let hash_password pwd =
  Base64.encode_exn(Cryptokit.hash_string (Cryptokit.Hash.sha256 ()) pwd)
;;

(*transforme une liste en tableau*)
let list_to_array(liste : 'a list) : 'a array = 
  let len : int = List.length liste in
  let list_tmp : 'a list ref=ref liste in 
  let tab : 'a array = Array.make len (List.hd liste) in
  for i=0 to len-1 do
    tab.(i)<-(List.hd !list_tmp);
    list_tmp := List.tl !list_tmp
  done;
  tab
;;

(*Renvoie un tableau contenant les mots de passe contenue dans un fichier*)
let read_mdp_en_clair file =
  let f = open_in file in
  let rec aux acc =
    try
      let login = input_line f 
      in
      aux (login :: acc)
    with End_of_file ->
      close_in f;
      List.rev acc
  in
  let list_mdp_clair : string list = aux [] in
  list_to_array(list_mdp_clair)
;;
(*read_mdp_en_clair("french_passwords_top20000.txt");;*)

(* add deux fichier et les mets sous forme de liste*)
let fusinfo ( files : string array): (string * string) list =
  let listconcaten : (string * string) list ref = ref []
  and len : int = Array.length files in
  for i=0 to len -1 do 
    listconcaten := (read_data_from_file files.(i)) @ !listconcaten
  done;
  let rec aux (listdep, listfin : (string * string) list *(string * string) list) : (string * string) list =
    if listdep = [] 
    then listfin
    else 
      (
        let listtmp : (string * string) list ref = ref listfin 
        and ispresent : bool ref = ref false in
        while !listtmp <> [] do 
          if List.hd listdep = List.hd !listtmp
          then ispresent := true ;
          listtmp :=  List.tl !listtmp
        done;
        if not (!ispresent) 
        then aux (List.tl listdep, (List.hd listdep) :: listfin)
        else aux (List.tl listdep,  listfin)
      )
  in aux(!listconcaten,[])
;;


(*let list = fusinfo([|"slogram01.txt";"slogram02.txt"|]);; *)

(*determine si un meme login est present dans plusieurs fuites de donnees (donc dans les fichiers
correspondant a plusieurs applications web) et dans ce cas determine si les mots de passe sont
identiques *)
let findbylogin (login_clear, files : (string * string) * (string * string) list ) : (string*string) =
  let listsamelog :  string list ref = ref [] in
    let listefile : (string * string ) list ref = ref files in
    while !listefile <> [] do
      if fst(List.hd !listefile) = fst(login_clear)
      then 
        ( 
          listsamelog := (snd(List.hd !listefile)) :: !listsamelog;
          listefile := List.tl !listefile
        )
      else 
        (
          listefile := List.tl !listefile
        )
    done;
  let mdp : string ref=ref "" in 
    while !listsamelog <> [] do
      if (List.hd !listsamelog) = hash_password(snd(login_clear))
      then mdp := snd(login_clear);
      listsamelog := List.tl !listsamelog
    done;
    (fst(login_clear),!mdp)
;;




let try_all_login (files : string array): (string * string * string) list =
  let result : (string * string * string) list ref = ref [] in
  let depen : (string * string) list ref = ref (fusinfo([|"depensetout01.txt";"depensetout02.txt"|])) in
  let info : (string * string) list = fusinfo(files) in 
  while !depen <> [] do
    let tmp : string * string  = findbylogin(List.hd !depen, info) in
    if snd(tmp) <> "" 
    then (
      let tmp2 : string * string * string = (fst(tmp), snd(tmp), files.(0)) in
      result := tmp2 :: !result 
    );
    depen := List.tl !depen
  done;
  !result
;;



try_all_login([|"slogram01.txt";"slogram02.txt"|]);;   



(*determine si un meme mot de passe hache est present dans plusieurs fuites de donnees et trouve
a quels logins ils sont associes*)
let findbypassword (password, files : string * (string * string) list ) : string * (string) list =
  let listsamepassword : string  list ref = ref [] in
  let listefile : (string * string) list  ref = ref files in
    while !listefile <> [] do
      if snd(List.hd !listefile) = password
      then 
        ( 
          listsamepassword := (fst(List.hd !listefile)) :: !listsamepassword;
          listefile := List.tl !listefile
        )
      else 
        (
          listefile := List.tl !listefile
        )
    done;
    (password, !listsamepassword) 
;; 

(*Etant donnee une liste de mots de passe en clair, extrait la liste des couples (application web,
login) pour lequel le mot de passe hache associe au login correspond au hache d’un des mots de
passe en clair*)
let try_all_password (file_pass, files : string array * (string array)): (string * (string list)) list =
  let len = Array.length (file_pass) in
  let result : (string * (string  list)) list ref = ref [] in
  let info : (string * string) list = fusinfo(files) in
  for i=0 to len -1 do
    let tmp : (string * (string list)) = findbypassword(hash_password(file_pass.(i)), info) in
    if (snd tmp) <> [] then (
      result := tmp :: !result
    )
  done;
  !result
;;







let find_matching_logins (clear_password, files : string array * string array) : (string * string * string) list =
  let samepasswords : (string * string * string) list ref = ref [] in
  let len_clear : int = Array.length clear_password in
  let len_files : int = Array.length files in 
  if len_clear = 0 || len_files = 0 then
    failwith "Error: clear passwords or files array is empty"
  else
    let info : (string * string) list = (fusinfo(files)) in
    for i = 0 to len_clear - 1 do
      let hashed_password : string = hash_password (clear_password.(i)) in 
      let data : (string * string) list ref = ref info in
        while !data <> [] do
          
          if snd (List.hd !data) = hashed_password then
            (
              samepasswords := (files.(0),fst (List.hd !data), clear_password.(i)) :: !samepasswords
            );
          data := List.tl !data
        done
    done;
  !samepasswords
;;




let tab : string array = [|"slogram01.txt";"slogram02.txt"|] in
List.length (find_matching_logins(read_mdp_en_clair("french_passwords_top20000.txt"),tab));;


let crackers():(string * string * string) list =
  let slogram : string array = [|"slogram01.txt";"slogram02.txt"|] in
  let tetedamis : string array = [|"tetedamis01.txt";"tetedamis02.txt"|] in
  let final: (string * string * string) list ref = ref [] in
  final := try_all_password(read_mdp_en_clair("french_passwords_top20000.txt"),slogram) @ !final;
  final := try_all_login (read_mdp_en_clair("french_passwords_top20000.txt"),tetedamis) @ !final;
  !final
;;


