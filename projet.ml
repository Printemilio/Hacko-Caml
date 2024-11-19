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


#use "topfind";;
#require "cryptokit";;
#require "base64";;
  
  
let hash_password pwd =
  Base64.encode_exn(Cryptokit.hash_string (Cryptokit.Hash.sha256 ()) pwd)
;;

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

