@load base/frameworks/sumstats

event zeek_init()
    {

    local r1 = SumStats::Reducer($stream="all_response", $apply=set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream="404_response", $apply=set(SumStats::SUM));
    local r3 = SumStats::Reducer($stream="404_url", $apply=set(SumStats::UNIQUE));

    SumStats::create([$name = "result_output",
                      $epoch = 10min,
                      $reducers = set(r1,r2,r3),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local all_res = result["all_response"];
                        local 404_res = result["404_response"];
                        local 404_u = result["404_url"];
                        if(404_res$sum>2&&(404_res$sum/all_res$sum)>0.2&&404_u$unique/404_res$sum)>0.5)
                        {
                                print fmt("%s is a scanner with %d scan attemps on %d urls", key$host,404_res$num,404_u$unique);
                        }

                        
                        }]);
    }
    
    event http_reply (c: connection, version: string, code: count, reason: string)
    {

    SumStats::observe("all_response",SumStats::Key($host=c$id$orig_h),SumStats::Observation($num=1));
    if(code==404)
    {
        SumStats::observe("404_response",SumStats::Key($host=c$id$orig_h),SumStats::Observation($num=1));
        SumStats::observe("404_url",SumStats::Key($host=c$id$orig_h),SumStats::Observation($str=c$http$uri));
    }
    }
