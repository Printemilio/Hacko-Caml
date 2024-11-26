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
  aux [];;

(*
#use "topfind";;
#require "cryptokit";;
#require "base64";;
  
  
let hash_password pwd =
  Base64.encode_exn(Cryptokit.hash_string (Cryptokit.Hash.sha256 ()) pwd)
;;
*)

let fusinfo ( file1,file2 : string * string): (string * string) list =
  let listefil1 : (string * string) list = read_data_from_file file1 
  and listefil2 : (string * string) list = read_data_from_file file2 in
  let listconcaten : (string * string) list = listefil1 @ listefil2 in 
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
  in aux(listconcaten,[])
;;

let list = fusinfo("depensetout01.txt","depensetout02.txt");;
list ;;

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

