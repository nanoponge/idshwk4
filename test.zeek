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
                                local rs1 = result["all_response"];
                                local rs2 = result["404_response"];
                                local rs3 = result["404_url"];
                         if (rs2$sum > 2)
                         {
                              if (rs2$sum / rs1$sum > 0.2) 
                              {
                                 if (rs3$unique / rs2$sum > 0.5) 
                                 print fmt(" %s is a scanner with %.0f scan attemps on %d urls", key$host, rs2$sum, rs3$unique); 
                              }
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
