--
-- Name: affected_products; Type: TABLE; Schema: public; Owner: postgres
--
CREATE TABLE public.affected_products (
    cve character(20) NOT NULL,
    vendor_name text,
    product_name text,
    version_value text
);
--ALTER TABLE public.affected_products OWNER TO postgres;

--
-- Name: cvss; Type: TABLE; Schema: public; Owner: postgres
--
CREATE TABLE public.cvss (
    cve character(20) NOT NULL,
    attack_complexity_3 character(5),
    attack_vector_3 character(20),
    availability_impact_3 character(5),
    confidentiality_impact_3 character(5),
    integrity_impact_3 character(5),
    privileges_required_3 character(5),
    scope_3 character(10),
    user_interaction_3 character(10),
    vector_string_3 character(50),
    exploitability_score_3 real,
    impact_score_3 real,
    base_score_3 real,
    base_severity_3 character(10),
    access_complexity character(10),
    access_vector character(20),
    authentication character(10),
    availability_impact character(10),
    confidentiality_impact character(10),
    integrity_impact character(10),
    obtain_all_privileges boolean,
    obtain_other_privileges boolean,
    obtain_user_privileges boolean,
    user_interaction_required boolean,
    vector_string character(50),
    exploitability_score real,
    impact_score real,
    base_score real,
    severity character(10),
    description text,
    published_date date,
    last_modified_date date
);
--ALTER TABLE public.cvss OWNER TO postgres;

--
-- Name: cvss_vs_products; Type: VIEW; Schema: public; Owner: postgres
--
CREATE VIEW public.cvss_vs_products WITH (security_barrier='false') AS
 SELECT cvss.cve,
    cvss.base_score_3,
    cvss.base_severity_3,
    cvss.base_score,
    cvss.severity,
    cvss.published_date,
    affected_products.vendor_name,
    affected_products.product_name,
    affected_products.version_value,
    cvss.description
   FROM public.affected_products,
    public.cvss
  WHERE (affected_products.cve = cvss.cve);
--ALTER TABLE public.cvss_vs_products OWNER TO postgres;

--
-- Name: count_affected_products_critical; Type: VIEW; Schema: public; Owner: postgres
--
CREATE VIEW public.count_affected_products_critical AS
 SELECT cvss_vs_products.product_name,
    count(cvss_vs_products.product_name) AS count
   FROM public.cvss_vs_products
  WHERE (cvss_vs_products.base_score_3 > (8.9)::double precision)
  GROUP BY cvss_vs_products.product_name
  ORDER BY (count(cvss_vs_products.product_name)) DESC;
--ALTER TABLE public.count_affected_products_critical OWNER TO postgres;

--
-- Name: count_products_per_severity; Type: VIEW; Schema: public; Owner: postgres
--
CREATE VIEW public.count_products_per_severity AS
 SELECT cvss_vs_products.product_name,
    cvss_vs_products.base_severity_3,
    count(*) AS count
   FROM public.cvss_vs_products
  GROUP BY cvss_vs_products.product_name, cvss_vs_products.base_severity_3;
--ALTER TABLE public.count_products_per_severity OWNER TO postgres;

--
-- Name: cpe; Type: TABLE; Schema: public; Owner: postgres
--
CREATE TABLE public.cpe (
    cve character(20) NOT NULL,
    cpe22uri text,
    cpe23uri text,
    vulnerable character(5)
);
--ALTER TABLE public.cpe OWNER TO postgres;

--
-- Name: critical_cves; Type: VIEW; Schema: public; Owner: postgres
--
CREATE VIEW public.critical_cves WITH (security_barrier='false') AS
 SELECT cvss.cve,
    cvss.base_score_3,
    cvss.base_severity_3,
    cvss.base_score,
    cvss.severity,
    affected_products.vendor_name,
    affected_products.product_name,
    affected_products.version_value,
    cvss.description
   FROM public.affected_products,
    public.cvss
  WHERE ((affected_products.cve = cvss.cve) AND ((cvss.base_severity_3 = 'CRITICAL'::bpchar) OR (cvss.severity = 'CRITICAL'::bpchar)));
--ALTER TABLE public.critical_cves OWNER TO postgres;

--
-- Name: cve_problem; Type: TABLE; Schema: public; Owner: postgres
--
CREATE TABLE public.cve_problem (
    cve character(20) NOT NULL,
    problem text
);
--ALTER TABLE public.cve_problem OWNER TO postgres;

--
-- Name: cvss_vs_cpes; Type: VIEW; Schema: public; Owner: postgres
--
CREATE VIEW public.cvss_vs_cpes AS
 SELECT cvss.cve,
    cvss.base_score_3,
    cvss.base_severity_3,
    cvss.base_score,
    cvss.severity,
    cpe.cpe23uri,
    cvss.description
   FROM public.cpe,
    public.cvss
  WHERE (cpe.cve = cvss.cve);
--ALTER TABLE public.cvss_vs_cpes OWNER TO postgres;