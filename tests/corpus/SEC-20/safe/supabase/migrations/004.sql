create view public.order_totals with (security_invoker = true) as select user_id, sum(total) from public.orders group by user_id;
