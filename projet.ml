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
  
  
let hash_password pwd =
  Base64.encode_exn(Cryptokit.hash_string (Cryptokit.Hash.sha256 ()) pwd)
;;

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
(*
read_mdp_en_clair("french_passwords_top20000.txt");;
*)

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


let list = fusinfo([|"slogram01.txt";"slogram02.txt"|]);; 

(*trouver le mot de passe d'un login si il se trouve dans plusieurs bases de donné*)

let findbylogin (login, files : string * (string array) ) : (string*string*(string list)) =
  let listsamelog : (string * string ) list ref = ref [] in
  let len : int = Array.length files in
  for i=0 to len-1 do
    let listefile : (string * string) list  ref = ref (read_data_from_file files.(i) ) in
    while !listefile <> [] do
      if fst(List.hd !listefile) = login
      then 
        ( 
          listsamelog := (snd(List.hd !listefile),files.(i)) :: !listsamelog;
          listefile := List.tl !listefile
        )
      else 
        (
          listefile := List.tl !listefile
        )
    done
  done;
  if !listsamelog = [] || List.length (!listsamelog) = 1 
  then failwith("Error findbylogin: this login did not occur in those files or just one time")
  else (
    let listsamelogcopie : (string * string ) list ref = ref (List.tl(!listsamelog)) in
    while not(fst(List.hd !listsamelogcopie) = fst(List.hd !listsamelog)) do
      if List.length(!listsamelog) = 1 then
        failwith("error no password match")
      else (
        if !listsamelogcopie <> [] then
          listsamelogcopie := List.tl !listsamelogcopie
        else (
          listsamelog := List.tl !listsamelog;
          listsamelogcopie := List.tl(!listsamelog)
        )
      )
    done;
    (login, fst(List.hd(!listsamelog)),[snd(List.hd(!listsamelog)); snd(List.hd(!listsamelogcopie))])   
  )
;;

(*trouver un login à partir d'un mots de passe haché*)

let findbypassword (password, files : string * (string array) ) : string * (string*string) list =
  let listsamepassword : (string * string ) list ref = ref [] in
  let len : int = Array.length files in
  for i=0 to len-1 do
    let listefile : (string * string) list  ref = ref (read_data_from_file files.(i) ) in
    while !listefile <> [] do
      if fst(List.hd !listefile) = password
      then 
        ( 
          listsamepassword := (snd(List.hd !listefile),files.(i)) :: !listsamepassword;
          listefile := List.tl !listefile
        )
      else 
        (
          listefile := List.tl !listefile
        )
    done
  done;
    (password, !listsamepassword) 
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
List.length (find_matching_logins(read_mdp_en_clair("french_passwords_top20000.txt"),tab))
