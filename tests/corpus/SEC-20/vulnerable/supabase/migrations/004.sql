create view public.order_totals as select user_id, sum(total) from public.orders group by user_id;
